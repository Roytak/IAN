/*
 *	IAN Project 1 - ELF files analysis
 *	File: ian-proj1.c
 *	Description: Prints information about ELF files.
 *	Author: Roman Janota
 *	Date: 26/02/2023
 */

#define _GNU_SOURCE

#include <assert.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ian-proj1.h"

char *
segment_type_to_str(int type)
{
	char *buf;

	/* dynamic memory because we dont know the length of an unknown type */

	switch (type) {
	case PT_NULL:
		return strdup("NULL");
	case PT_LOAD:
		return strdup("LOAD");
	case PT_DYNAMIC:
		return strdup("DYNAMIC");
	case PT_INTERP:
		return strdup("INTERP");
	case PT_NOTE:
		return strdup("NOTE");
	case PT_SHLIB:
		return strdup("SHLIB");
	case PT_PHDR:
		return strdup("PHDR");
	case PT_TLS:
		return strdup("TLS");
	case PT_GNU_PROPERTY:
		return strdup("GNU_PROPERTY");
	case PT_GNU_EH_FRAME:
		return strdup("GNU_EH_FRAME");
	case PT_GNU_STACK:
		return strdup("GNU_STACK");
	case PT_GNU_RELRO:
		return strdup("GNU_RELRO");
	default:
		asprintf(&buf, "%d", type);
		return buf;
	}
}

const char *
flags_to_str(int flags)
{
	if ((flags & 0x07) == 0x07) {
		return "RWX";
	} else if ((flags & 0x06) == 0x06) {
		return "RW-";
	} else if ((flags & 0x05) == 0x05) {
		return "R-X";
	} else if ((flags & 0x04) == 0x04) {
		return "R--";
	} else if ((flags & 0x03) == 0x03) {
		return "-WX";
	} else if ((flags & 0x02) == 0x02) {
		return "-W-";
	} else if ((flags & 0x01) == 0x01) {
		return "--X";
	} else {
		return "---";
	}
}

void
print_data(unsigned int id, const char *mode, const char *segment_name, const char *sections, int ws_count)
{
	ws_count = ws_count - strlen(segment_name) + 4;

	if (!sections) {
		printf("%.2d    %s%*c%s\n", id, segment_name, ws_count, ' ', mode);
	} else {
		printf("%.2d    %s%*c%s    %s\n", id, segment_name, ws_count, ' ', mode, sections);
	}
}

int
init(char *filename, int *fd, Elf **e)
{
	int ret = 0;

	assert(fd);
	assert(e);

	*fd = open(filename, O_RDONLY, 0);
	if (*fd < 0) {
		ERR_MSG_CLEANUP("Unable to open file.");
	}

	/* set elf version */
	if (elf_version(EV_CURRENT) == EV_NONE) {
		ERR_ELF_MSG_CLEANUP;
	}

	/* create a new elf handle */
	*e = elf_begin(*fd, ELF_C_READ, NULL);
	if (!*e) {
		ERR_ELF_MSG_CLEANUP;
	}

	/* check if the file is an elf file */
	if (elf_kind(*e) != ELF_K_ELF) {
		ERR_MSG_CLEANUP("Only elf files are supported.");
	}

cleanup:
	return ret;
}

int
fill_sections(Elf *e, struct section **sections, unsigned int *section_count)
{
	int ret = 0;
	Elf_Scn *scn;
	char *name;
	size_t sh_idx;
	void *tmp;
	GElf_Shdr shdr;

	/* get the index of the section name string table */
	if (elf_getshdrstrndx(e, &sh_idx)) {
		ERR_ELF_MSG_CLEANUP;
	}

	scn = NULL;
	while ((scn = elf_nextscn(e, scn)) != NULL) {
		/* iterate over all the sections */
		if (!gelf_getshdr(scn, &shdr)) {
			ERR_MSG_CLEANUP("Getting section header failed.");
		}

		name = elf_strptr(e, sh_idx, shdr.sh_name);
		if (!name) {
			ERR_ELF_MSG_CLEANUP;
		}

		tmp = realloc(*sections, (*section_count + 1) * sizeof **sections);
		if (!tmp) {
			ERR_MSG_CLEANUP("Memory allocation error.");
		}
		*sections = tmp;
		(*sections)[*section_count].name = strdup(name);
		memcpy(&(*sections)[*section_count].shdr, &shdr, sizeof shdr);
		(*section_count)++;
	}

cleanup:
	return ret;
}

int
append_section_name(const char *sec_name, char **buffer)
{
	int ret = 0;
	void *tmp;

	if (!*buffer) {
		/* first call */
		*buffer = calloc(1, strlen(sec_name) + 2);
		if (!*buffer) {
			ERR_MSG_CLEANUP("Memory allocation error.");
		}
		sprintf(*buffer, "%s ", sec_name);
	} else {
		/* append the current section name to the previous sections */
		tmp = realloc(*buffer, strlen(*buffer) + strlen(sec_name) + 2);
		if (!tmp) {
			ERR_MSG_CLEANUP("Memory allocation error.");
		}
		*buffer = tmp;
		memset(*buffer + strlen(*buffer), 0, strlen(sec_name) + 2);
		*buffer = strcat(*buffer, " ");
		*buffer = strcat(*buffer, sec_name);
	}

cleanup:
	return ret;
}

int
section_in_segment(GElf_Shdr section, GElf_Phdr segment)
{
	int offset_ok = 0;

	if (section.sh_type == SHT_NOBITS) {
		/* if it has no size, then we don't care about offsets */
		offset_ok = 1;
	} else {
		/* else the section's offset has to be within the segment's offset and it's size */
		if ((section.sh_offset >= segment.p_offset)) {
			if ((section.sh_offset - segment.p_offset) <= (segment.p_filesz - 1)) {
				if ((section.sh_offset - segment.p_offset + section.sh_size) <= segment.p_filesz) {
					offset_ok = 1;
				}
			}
		}
	}

	if (offset_ok) {
		/* do the same for memory addresses */
		if ((section.sh_flags & SHF_ALLOC) == 0) {
			return 1;
		} else {
			if (section.sh_addr >= segment.p_vaddr) {
				if ((section.sh_addr - segment.p_vaddr) <= segment.p_memsz - 1) {
					if (((section.sh_addr - segment.p_vaddr + section.sh_size) <= segment.p_memsz)) {
						return 1;
					}
				}
			}
		}
	}

	return 0;
}

char *
map_sections_to_segment(struct section *sections, GElf_Phdr segment, unsigned int section_count, int *ret)
{
	unsigned int i;
	char *buffer = NULL;

	for (i = 0; i < section_count; i++) {
		if (section_in_segment(sections[i].shdr, segment)) {
			/* section lies in the segment */
			if (append_section_name(sections[i].name, &buffer)) {
				*ret = 1;
				return NULL;
			}
		}
	}

	return buffer;
}

int
max_segment_name_len(Elf *e, int segment_count)
{
	int len, i, max_len = 0, ret = 0;
	GElf_Phdr phdr;
	char *segment_type;

	for (i = 0; i < segment_count; i++) {
		if (!gelf_getphdr(e, i, &phdr)) {
			ERR_MSG_CLEANUP("Unable to get segment header.");
		}

		/* convert segment type to a string */
		segment_type = segment_type_to_str(phdr.p_type);
		if (!segment_type) {
			ERR_MSG_CLEANUP("Memory allocation error.");
		}

		len = strlen(segment_type);
		if (len > max_len) {
			max_len = len;
		}

		free(segment_type);
	}

cleanup:
	return ret ? ret : max_len;
}

int
get_segments(Elf *e, struct section *sections, unsigned int section_count)
{
	int ret = 0, max_len;
	size_t n, i;
	GElf_Phdr phdr;
	char *buffer, *segment_type;

	/* get number of segments */
	if (elf_getphdrnum(e, &n)) {
		ERR_ELF_MSG_CLEANUP;
	}

	/* get maximum header name length for formatting later */
	max_len = max_segment_name_len(e, n);
	if (max_len == -1) {
		ERR_MSG_CLEANUP("Memory allocation error.");
	}

	for (i = 0; i < n; i++) {
		if (!gelf_getphdr(e, i, &phdr)) {
			ERR_MSG_CLEANUP("Unable to get header.");
		}

		/* store sections which belong to the segment in buffer */
		buffer = map_sections_to_segment(sections, phdr, section_count, &ret);
		if (ret) {
			ERR_MSG_CLEANUP("Mappinng sections to segments failed.");
		}

		segment_type = segment_type_to_str(phdr.p_type);
		if (!segment_type) {
			ERR_MSG_CLEANUP("Memory allocation error.");
		}

		print_data(i, flags_to_str(phdr.p_flags), segment_type, buffer, max_len);
		free(buffer);
		free(segment_type);
	}

cleanup:
	return ret;
}

int
main(int argc, char *argv[])
{
	int ret = 0;
	int fd = -1;
	Elf *e = NULL;
	struct section *sections = NULL;
	unsigned int section_count = 0, i;

	if (argc != 2) {
		ERR_MSG_CLEANUP("Usage: ian-proj1 <FILE>.");
	}

	if (init(argv[1], &fd, &e)) {
		ERR_MSG_CLEANUP("Initialization failed.");
	}

	if (fill_sections(e, &sections, &section_count)) {
		ERR_MSG_CLEANUP("Filling sections failed.");
	}

	if (get_segments(e, sections, section_count)) {
		ERR_MSG_CLEANUP("Getting segments failed.");
	}

cleanup:
	if (fd >= 0) {
		close(fd);
	}
	elf_end(e);
	for (i = 0; i < section_count; i++) {
		free(sections[i].name);
	}
	free(sections);
	return ret;
}
