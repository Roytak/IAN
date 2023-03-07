/*
 *	IAN Project 1 - ELF files analysis
 *	File: ian-proj1.h
 *	Author: Roman Janota
 *	Date: 26/02/2023
 */

#ifndef _IAN_PROJ1_H_
#define _IAN_PROJ1_H_

#define ERR_MSG_CLEANUP(err) fprintf(stderr, "[ERR]: %s\n", err); ret = -1; goto cleanup
#define ERR_ELF_MSG_CLEANUP fprintf(stderr, "[ELF_ERR]: \"%s\"\n", elf_errmsg(elf_errno())); ret = -1; goto cleanup

struct section {
  GElf_Shdr shdr;
  char *name;
};

#endif
