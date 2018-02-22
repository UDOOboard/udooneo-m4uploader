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

#include "mqx_upload_on_m4SoloX.h"
#define VERSION			"2.1.0"
#define NAME_OF_BOARD	"UDOO Neo"

int fd;

void send_m4_stop_flag(unsigned char value) {
	off_t target;
	void *map_base, *virt_addr;

	target = ADDR_SHARED_BYTE_FOR_M4STOP;
	map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, target & ~MAP_MASK);
	virt_addr = (unsigned char *)map_base + (target & MAP_MASK);
	*((unsigned char *) virt_addr) = value;
	munmap(map_base, MAP_SIZE);
}

void reset_m4_trace_flag() {
	off_t target;
	void *map_base, *virt_addr;

	target = ADDR_SHARED_TRACE_FLAGS;
	map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, target & ~MAP_MASK);
	virt_addr = (unsigned char *)map_base + (target & MAP_MASK);
	*((int *) virt_addr) = 0L;
	munmap(map_base, MAP_SIZE);
}

int get_m4_trace_flag() {
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

void set_gate_m4_clk() {
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

void srcscr_set_bit(unsigned int set_mask) {
	void *virt_addr;
	unsigned long read_result;
	virt_addr = mmap(0, SIZE_4BYTE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t) ADDR_SRC_SCR);
	read_result = *((unsigned long *) virt_addr);
	*((unsigned long *) virt_addr) = read_result | set_mask;
	munmap(virt_addr, SIZE_4BYTE);
}

void srcscr_unset_bit(unsigned int unset_mask) {
	void *virt_addr;
	unsigned long read_result;
	virt_addr = mmap(0, SIZE_4BYTE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t) ADDR_SRC_SCR);
	read_result = *((unsigned long *) virt_addr);
	*((unsigned long *) virt_addr) = read_result & unset_mask;
	munmap(virt_addr, SIZE_4BYTE);
}

void set_stack_pc(unsigned int stack, unsigned int pc) {
	off_t target = (off_t) ADDR_STACK_PC;
	void *map_base, *virt_addr;
	map_base = mmap(0, SIZE_16BYTE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t) target);
	virt_addr = (unsigned char *)map_base + (target & MAP_MASK);
	*((unsigned long *) virt_addr) = stack;
	virt_addr = (unsigned char *)map_base + ((target + 0x4) & MAP_MASK);
	*((unsigned long *) virt_addr) = pc;
	munmap(map_base, SIZE_16BYTE);
}

int load_m4_fw(char *filepath, unsigned int loadaddr) {
	int size;
	FILE *firmware;
	char *filebuffer;
	void *map_base, *virt_addr;
	unsigned long stack, pc;

	firmware = fopen(filepath, "rb");
	fseek(firmware, 0, SEEK_END);
	size = ftell(firmware);
	fseek(firmware, 0, SEEK_SET);
	if (size > MAX_FILE_SIZE) {
		LogError("%s - File size too big, can't load: %d > %d \n", NAME_OF_BOARD, size, MAX_FILE_SIZE);
		return -2;
	}
	filebuffer = (char *)malloc(size+1);
	if (size != fread(filebuffer, sizeof(char), size, firmware)) {
		free(filebuffer);
		return -2;
	}

	fclose(firmware);

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

	set_stack_pc(stack, pc);
	free(filebuffer);

	return size;
}

void send_rpmsg_magic() {
	FILE *fd_ttyrpmsg;
	fd_ttyrpmsg=fopen("/dev/ttyRPMSG", "w");
	fwrite(HANDSHAKE_MSG, sizeof(HANDSHAKE_MSG), 1, fd_ttyrpmsg);
	fclose(fd_ttyrpmsg);
}

void debugTraceFlags(int traceFlags) {
	char str[200];

	if (traceFlags == 0) {
		printf("0x00000000 => no flags set\n");
		return;
	}
	strcpy(str, "");

	if ((traceFlags & TRACE01_TOOLCHAIN_STARTUP) == TRACE01_TOOLCHAIN_STARTUP) {
		strcat(str, "toolchain, ");
	}
	if ((traceFlags & TRACE02_MAIN_CALLED) == TRACE02_MAIN_CALLED) {
		strcat(str, "main, ");
	}
	if ((traceFlags & TRACE03_MQX_STARTED) == TRACE03_MQX_STARTED) {
		strcat(str, "mqx, ");
	}
	if ((traceFlags & TRACE04_BSP_PRE_INIT) == TRACE04_BSP_PRE_INIT) {
		strcat(str, "preinit, ");
	}
	if ((traceFlags & TRACE05_BSP_INIT) == TRACE05_BSP_INIT) {
		strcat(str, "init, ");
	}
	if ((traceFlags & TRACE06_MAIN_TASK_RUN) == TRACE06_MAIN_TASK_RUN) {
		strcat(str, "maintask, ");
	}
	if ((traceFlags & TRACE07_EXIT_TASK_RUN) == TRACE07_EXIT_TASK_RUN) {
		strcat(str, "exit, ");
	}
	if ((traceFlags & TRACE08_ARDUINO_LOOP_TASK_RUN) == TRACE08_ARDUINO_LOOP_TASK_RUN) {
		strcat(str, "arduino loop, ");
	}
	if ((traceFlags & TRACE09_ARDUINO_YIELD_TASK_RUN) == TRACE09_ARDUINO_YIELD_TASK_RUN) {
		strcat(str, "arduino yeld, ");
	}
	if ((traceFlags & TRACE10_MCC_RX_TASK_RUN) == TRACE10_MCC_RX_TASK_RUN) {
		strcat(str, "mcc rx, ");
	}
	if ((traceFlags & TRACE11_UART_RX_TASK_RUN) == TRACE11_UART_RX_TASK_RUN) {
		strcat(str, "uart rx, ");
	}
	if ((traceFlags & TRACE12_MQX_EXIT) == TRACE12_MQX_EXIT) {
		strcat(str, "mqx exit, ");
	}
	if ((traceFlags & TRACE13_RPMSG_INIT_LOCKED) == TRACE13_RPMSG_INIT_LOCKED) {
		strcat(str, "rpmsg init, ");
	}
	if ((traceFlags & TRACE14_RPMSG_TX_CHANNEL) == TRACE14_RPMSG_TX_CHANNEL) {
		strcat(str, "rpmsg tx, ");
	}
	if ((traceFlags & TRACE15_RPMSG_RX_TASK_RUN) == TRACE15_RPMSG_RX_TASK_RUN) {
		strcat(str, "rpmsg rx, ");
	}

	str[strlen(str)-2] = '\0';
	printf("0x%08x => %s\n", traceFlags, str);
}

int is_m4_started() {
	int traceFlags = 0,
		lastTraceFlags = -1,
		retry = MAX_RETRIES;

	while (retry > 0) {
		usleep(200000);
		retry--;
		traceFlags = get_m4_trace_flag();
		if (traceFlags != lastTraceFlags) {
			debugTraceFlags(traceFlags);
			lastTraceFlags = traceFlags;
		}

		if ((traceFlags & SKETCH_TASKS_RUNNING) == SKETCH_TASKS_RUNNING) {
			// if all tasks are running, consider the sketch running
			break;
		}
	}
	
	traceFlags = get_m4_trace_flag();
	if ((traceFlags & RPMSG_NEEDS_UNLOCK) != 0) {
		// if locked, try to unlock RPMSG
		LogDebug("%s - M4 firmware is running, however RPMSG is locked!\n", NAME_OF_BOARD);
		LogDebug("%s - Unlocking remote processor...\n", NAME_OF_BOARD);
		usleep(2000000);
		send_rpmsg_magic();
		usleep(8000000);
	}

	traceFlags = get_m4_trace_flag();
	debugTraceFlags(traceFlags);
	if ((traceFlags & SKETCH_TASKS_RUNNING) == SKETCH_TASKS_RUNNING) {
		// if after unlocking RPMSG all tasks are now running, consider the sketch running
		return 1;
	}
	if ((traceFlags & TRACE_FLAG_EXIT_TASK) == TRACE_FLAG_EXIT_TASK) {
		// if after unlocking RPMSG only exit task is running, consider the sketch unlockable
		return 3;
	}

	// sketch is not running
	return 0;
}

int stop_m4_firmware() {
	int traceFlags = 0,
		lastTraceFlags = -1,
		m4IsStopped = 0,
		retry = MAX_RETRIES;

	reset_m4_trace_flag();
	// send stop M4 firmware command
	send_m4_stop_flag(0xAA);		//(replace m4_stop tool function)
	usleep(100000);

	while ((m4IsStopped == 0) && (retry>0)) {
		traceFlags = get_m4_trace_flag();
		if (traceFlags != lastTraceFlags) {
			debugTraceFlags(traceFlags);
			lastTraceFlags = traceFlags;
		}
		if((traceFlags & TRACE_FLAG_MQX_EXIT) != 0) {
			m4IsStopped = 1;
			LogDebug("%s - Stopped M4 firmware\n", NAME_OF_BOARD);
		}
		usleep(100000);
		retry--;
	}

	// clean stop flag, for the next firmware
	send_m4_stop_flag(0x00);
	if (m4IsStopped == 0) {
		return -1;
	}

	usleep(500000);	// for execute _mqx_exit
	return 0;
}

int is_m4_running() {
	return get_m4_trace_flag() != 0;
}

int main(int argc, char **argv) {
	int m4IsRunning = 0;
	unsigned long loadaddr;
	char *p;
	char *filepath = argv[1];

	LogDebug("%s - MQX uploader v. %s\n", NAME_OF_BOARD, VERSION);

	if (argc < 2) {
		LogError("%s - Usage: %s <project_name> [0xLOADADDR]\n", NAME_OF_BOARD, argv[0]);
		return RETURN_CODE_ARGUMENTS_ERROR;
	}

	if (access(filepath, F_OK) == -1) {
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
	// check if the firmware is running, and try to stop it
	// ======================================================================
	if (is_m4_running()) {
		LogDebug("%s - M4 firmware is running, stopping it\n", NAME_OF_BOARD);
		if (stop_m4_firmware() < 0) {
			LogError("%s - Failed to Stop M4 firmware: please reboot your system!\n", NAME_OF_BOARD);
			close(fd);
			return RETURN_CODE_M4STOP_FAILED;
		}
	} else {
		LogDebug("%s - M4 firmware was not running\n", NAME_OF_BOARD);
	}

	// ======================================================================
	// upload new firmware
	// ======================================================================
	LogDebug("%s - Uploading new M4 firmware...\n", NAME_OF_BOARD);
	srcscr_set_bit(M4c_RST);
	set_gate_m4_clk();
	load_m4_fw(filepath, loadaddr);
	srcscr_unset_bit(~M4c_RST);
	LogDebug("%s - M4 firmware upload complete!\n", NAME_OF_BOARD);
		
	// ======================================================================
	// wait/check if the new firmware is running
	// ======================================================================
	m4IsRunning = is_m4_started();
	if (m4IsRunning == 0) {
		LogError("%s - Failed to Start M4 firmware. Please try to reboot the board!\n", NAME_OF_BOARD);
		close(fd);
		exit(RETURN_CODE_M4START_FAILED);
	} else {
		if (m4IsRunning == 1) {
			LogDebug("%s - M4 firmware is running!\n", NAME_OF_BOARD);
		} else {
			LogDebug("%s - WARNING: M4 firmware is running, however loops are blocked!\n", NAME_OF_BOARD);
		}
		close(fd);
		exit(RETURN_CODE_OK);
	}
}

