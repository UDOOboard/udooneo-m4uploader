/*
 * mqx_upload_on_m4SoloX.c operations to load fw and startup M4 core
 *
 * Copyright (C) 2015-2016 Giuseppe Pagano <giuseppe.pagano@seco.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/mman.h>

#ifdef ANDROID
#define LOG_TAG "M4Uploader"
#include <cutils/log.h>
#define LogDebug ALOGD
#define LogError ALOGE
#else
#define LogDebug printf
#define LogError printf
#endif

#define VERSION         "1.2.0"
#define NAME_OF_BOARD   "UDOO Neo"

#define MAP_SIZE        4096UL
#define MAP_MASK        (MAP_SIZE - 1)
#define SIZE_4BYTE      4UL
#define SIZE_16BYTE     16UL
#define MAP_OCRAM_SIZE  512*1024
#define MAP_OCRAM_MASK  (MAP_OCRAM_SIZE - 1)
#define MAX_FILE_SIZE   MAP_OCRAM_SIZE
#define MAX_RETRIES     8

#define ADDR_STACK_PC                   0x007F8000
#define ADDR_SRC_SCR                    0x020D8000
#define M4c_RST                         (1 << 4)
#define ADDR_GATE_M4_CLOCK              0x020C4074
#define GATE_M4_CLOCK                   0x0000000C

#define ADDR_SHARED_TRACE_FLAGS         0xBFF0FFF4 // address in shared RAM for M4 trace flags
#define ADDR_SHARED_BYTE_FOR_M4STOP     0xBFF0FFFF // to force M4 sketch to secure exit
#define TRACE_FLAG_TOOLCHAIN_STARTUP    0x00000001
#define TRACE_FLAG_MAIN                 0x00000002
#define TRACE_FLAG_MQX                  0x00000004
#define TRACE_FLAG_BSP_PRE_INIT         0x00000008
#define TRACE_FLAG_BSP_INIT             0x00000010
#define TRACE_FLAG_MAIN_TASK            0x00000020
#define TRACE_FLAG_EXIT_TASK            0x00000040
#define TRACE_FLAG_ARDUINO_LOOP         0x00000080
#define TRACE_FLAG_YIELD_LOOP           0x00000100
#define TRACE_FLAG_MQX_MCCUART_RECEIVE  0x00000200
#define TRACE_FLAG_MQX_UART_RECEIVE     0x00000400
#define TRACE_FLAG_MQX_EXIT             0x00000800

#define SKETCH_RUNNING                  (TRACE_FLAG_MAIN_TASK | TRACE_FLAG_EXIT_TASK)
#define SKETCH_TASKS_RUNNING            (SKETCH_RUNNING | TRACE_FLAG_ARDUINO_LOOP | TRACE_FLAG_YIELD_LOOP)

#define RETURN_CODE_OK                  0
#define RETURN_CODE_ARGUMENTS_ERROR     1
#define RETURN_CODE_M4STOP_FAILED       2
#define RETURN_CODE_M4START_FAILED      3

void send_m4_stop_flag(int fd, unsigned char value) {
	off_t target;
	void *map_base, *virt_addr;

	target = ADDR_SHARED_BYTE_FOR_M4STOP;
	map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, target & ~MAP_MASK);
	virt_addr = (unsigned char *)map_base + (target & MAP_MASK);
	*((unsigned char *) virt_addr) = value;
	munmap(map_base, MAP_SIZE);
}

void reset_m4_trace_flag(int fd) {
	off_t target;
	void *map_base, *virt_addr;

	target = ADDR_SHARED_TRACE_FLAGS;
	map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, target & ~MAP_MASK);
	virt_addr = (unsigned char *)map_base + (target & MAP_MASK);
	*((int *) virt_addr) = 0L;
	munmap(map_base, MAP_SIZE);
}

int get_m4_trace_flag(int fd) {
	off_t target;
	void *map_base, *virt_addr;
	int value;

	target = ADDR_SHARED_TRACE_FLAGS;
	map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, target & ~MAP_MASK);
	virt_addr = (unsigned char *)map_base + (target & MAP_MASK);
	value = *((int *) virt_addr);
	munmap(map_base, MAP_SIZE);
	return (value);
}

void set_gate_m4_clk(int fd) {
	off_t target;
	unsigned long read_result;
	void *map_base, *virt_addr;

	target = ADDR_GATE_M4_CLOCK;
	map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, target & ~MAP_MASK);
	virt_addr = (unsigned char *)map_base + (target & MAP_MASK);
	read_result = *((unsigned long *) virt_addr);
	*((unsigned long *) virt_addr) = read_result | GATE_M4_CLOCK;
	munmap(map_base, MAP_SIZE);
}

void srcscr_set_bit(int fd, unsigned int set_mask) {
	void *virt_addr;
	unsigned long read_result;
	virt_addr = mmap(0, SIZE_4BYTE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t) ADDR_SRC_SCR);
	read_result = *((unsigned long *) virt_addr);
	*((unsigned long *) virt_addr) = read_result | set_mask;
	munmap(virt_addr, SIZE_4BYTE);
}

void srcscr_unset_bit(int fd, unsigned int unset_mask) {
	void *virt_addr;
	unsigned long read_result;
	virt_addr = mmap(0, SIZE_4BYTE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t) ADDR_SRC_SCR);
	read_result = *((unsigned long *) virt_addr);
	*((unsigned long *) virt_addr) = read_result & unset_mask;
	munmap(virt_addr, SIZE_4BYTE);
}

void set_stack_pc(int fd, unsigned int stack, unsigned int pc) {
	off_t target = (off_t) ADDR_STACK_PC;
	unsigned long read_result;
	void *map_base, *virt_addr;
	map_base = mmap(0, SIZE_16BYTE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t) target);
	virt_addr = (unsigned char *)map_base + (target & MAP_MASK);
	*((unsigned long *) virt_addr) = stack;
	virt_addr = (unsigned char *)map_base + ((target + 0x4) & MAP_MASK);
	*((unsigned long *) virt_addr) = pc;
	munmap(map_base, SIZE_16BYTE);
}

int load_m4_fw(int fd, char *filepath, unsigned int loadaddr) {
	int n;
	int size;
	FILE *fdf;
	off_t target;
	char *filebuffer;
	void *map_base, *virt_addr;
	unsigned long stack, pc;

	fdf = fopen(filepath, "rb");
	fseek(fdf, 0, SEEK_END);
	size = ftell(fdf);
	fseek(fdf, 0, SEEK_SET);
	if (size > MAX_FILE_SIZE) {
		LogError("%s - File size too big, can't load: %d > %d \n", NAME_OF_BOARD, size, MAX_FILE_SIZE);
		return -2;
	}
	filebuffer = (char *)malloc(size+1);
	if (size != fread(filebuffer, sizeof(char), size, fdf)) {
		free(filebuffer);
		return -2;
	}

	fclose(fdf);

	stack = (filebuffer[0] | (filebuffer[1] << 8) | (filebuffer[2] << 16) | (filebuffer[3] << 24));
	pc = (filebuffer[4] | (filebuffer[5] << 8) | (filebuffer[6] << 16) | (filebuffer[7] << 24));

	if (loadaddr == 0x0) {
		loadaddr = pc & 0xFFFF0000;
	}
	LogDebug("%s - FILENAME = %s; loadaddr = 0x%08x\n", NAME_OF_BOARD, filepath, loadaddr);

	map_base = mmap(0, MAP_OCRAM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, loadaddr & ~MAP_OCRAM_MASK);
	LogDebug("%s - start - end (0x%08x - 0x%08x)\n", NAME_OF_BOARD, loadaddr & ~MAP_OCRAM_MASK, (loadaddr & ~MAP_OCRAM_MASK) + MAP_OCRAM_SIZE);
	virt_addr = (unsigned char *)map_base + (loadaddr & MAP_OCRAM_MASK);
	memcpy(virt_addr, filebuffer, size);
	munmap(map_base, MAP_OCRAM_SIZE);

	set_stack_pc(fd, stack, pc);
	free(filebuffer);

	return size;
}

int main(int argc, char **argv) {
	int fd, n;
	unsigned long loadaddr;
	char *p;
	char m4IsStopped = 0;
	char m4IsRunning = 0;
	int m4TraceFlags=0;
	int m4Retry;
	char *filepath = argv[1];

	LogDebug("%s - MQX uploader v. %s\n", NAME_OF_BOARD, VERSION);

	if (argc < 2) {
		LogError("%s - Usage: %s <project_name> [0xLOADADDR]\n", NAME_OF_BOARD, argv[0]);
		return (RETURN_CODE_ARGUMENTS_ERROR);
	}

	if(access(filepath, F_OK) == -1) {
		LogError("File %s not found.\n", argv[1]);
		return RETURN_CODE_ARGUMENTS_ERROR;
	}

	if (argc == 3) {
		loadaddr = strtoul(argv[2], &p, 16);
	} else {
		loadaddr = 0x0;
	} 
	
	fd = open("/dev/mem", O_RDWR | O_SYNC);

	// ======================================================================
	// check if the sketch is running
	// ======================================================================
	if (get_m4_trace_flag(fd) != 0) {
		reset_m4_trace_flag(fd);
		// do stop M4 sketch command
		send_m4_stop_flag(fd, 0xAA);		//(replace m4_stop tool function)
		m4Retry=MAX_RETRIES;
		while ((m4IsStopped == 0) && (m4Retry>0)) {
			usleep(300000);
			m4Retry--;
			m4TraceFlags = get_m4_trace_flag(fd);
			LogDebug("%s - Waiting M4 Stop, m4TraceFlags: %08X \n", NAME_OF_BOARD, m4TraceFlags);
			if((m4TraceFlags & TRACE_FLAG_MQX_EXIT) != 0) {
				m4IsStopped = 1;
				LogDebug("%s - Stopped M4 sketch \n", NAME_OF_BOARD);
			}
		}
		send_m4_stop_flag(fd, 0x00);
		if (m4IsStopped == 0) {
			LogError("%s - Failed to Stop M4 sketch: reboot system ! \n", NAME_OF_BOARD);
			close(fd);
			exit (RETURN_CODE_M4STOP_FAILED);
		}
		usleep(300000);	// for execute _mqx_exit
	}
	// ======================================================================
	// end check if the sketch is running
	// ======================================================================

	srcscr_set_bit(fd, (M4c_RST));
	set_gate_m4_clk(fd);
	load_m4_fw(fd, filepath, loadaddr);
	srcscr_unset_bit(fd, ~(M4c_RST));

	// ======================================================================
	// check if the new sketch is running
	// ======================================================================
	m4Retry=MAX_RETRIES;
	while ((m4IsRunning == 0) && (m4Retry>0)){
		usleep(300000);
		m4Retry--;
		m4TraceFlags = get_m4_trace_flag(fd);
		LogDebug("%s - Waiting M4 Run, m4TraceFlags: %08X \n", NAME_OF_BOARD, m4TraceFlags);
		if ((m4TraceFlags & SKETCH_TASKS_RUNNING) == SKETCH_TASKS_RUNNING) {
			m4IsRunning = 1;
			LogDebug("%s - M4 sketch is running!\n", NAME_OF_BOARD);
		}
	}
	
	if (m4IsRunning == 0) {
		m4TraceFlags = get_m4_trace_flag(fd);
		if ((m4TraceFlags & SKETCH_RUNNING) == SKETCH_RUNNING) {
			m4IsRunning = 1;
			LogDebug("%s - WARNING: M4 sketch is running, but setup() is blocking the execution!\n", NAME_OF_BOARD);
		}
	}
	
	if (m4IsRunning == 0) {
		LogError("%s - Failed to Start M4 sketch. Please try to reboot the board!\n", NAME_OF_BOARD);
		close(fd);
		exit (RETURN_CODE_M4START_FAILED);
	}
	// ======================================================================
	// end check if the new sketch is running
	// ======================================================================

	close(fd);
	exit (RETURN_CODE_OK);
}

