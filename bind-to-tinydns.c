#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define LINE_LEN 8192
#define DOMAIN_LEN 255
#define MAX_TOKENS 32
#define MAX_PAREN 3
#define DEFAULT_TTL 86400

#define DOMAIN_STR_LEN (DOMAIN_LEN * 4 + 1)

FILE *file = NULL;
char *filename = NULL;

/* warning: prints a warning message to stderr */
void warning (const char *message, int line_number)
{
	if (line_number > 0)
		fprintf (stderr, "warning: line %d: %s\n",
			 line_number, message);
	else fprintf (stderr, "warning: %s\n", message);
}

/* fatal: prints an error message with line number, closes and unlinks temp
 * file if necessary, and exits */
void fatal (const char *message, int line_number)
{
	if (line_number > 0)
		fprintf (stderr, "fatal: line %d: %s\n",
			 line_number, message);
	else fprintf (stderr, "fatal: %s\n", message);

	if (file) {
		if (fclose (file)) {
			fprintf (stderr, "unable to close temp file: %s\n",
				 strerror (errno));
		} else if (unlink (filename)) {
			fprintf (stderr, "unable to unlink temp file: %s\n",
				 strerror (errno));
		}
	}
	exit (1);
}

/* sanitize_string: sanitizes the BIND-escaped string in src and copies it
 * to array dest of length dest_len.  escaped characters are printed as
 * their tinydns-data counterparts.  dest_len must be <= LINE_LEN.  a
 * temporary string is used, so dest and src can point to the same memory.
 * returns 0 on success and 1 otherwise. */
int sanitize_string (char *dest, int dest_len, const char *src)
{
	char temp[LINE_LEN] = "";
	int i, j, src_len;

	if (!dest || !src) {
		warning ("sanitize_string: missing src or dest string", -1);
		return 1;
	}
	if (dest_len > LINE_LEN) {
		warning ("sanitize_string: dest string longer than "
			 "temp string", -1);
		return 1;
	}
	src_len = strlen (src);

	for (i = 0, j = 0; i < src_len; i++) {

		if (isprint (src[i]) && src[i] != '\\' && src[i] != ':') {
			if (j + 1 >= dest_len) {
				warning ("sanitize_string: src string "
					 "too long (for single printable "
					 "character)", -1);
				return 1;
			}
			temp[j] = src[i];
			j++;
		} else if (src[i] == '\\') {
			if (i + 1 >= src_len) {
				warning ("sanitize_string: backslash escape "
					 "in src string with no escaped "
					 "char", -1);
				return 1;
			}
			if (!isdigit (src[i+1])) {
				if (src[i+1] == ':' || src[i+1] == '\\' ||
				    src[i+1] == '.' || !isprint (src[i+1])) {
					if (j + 4 >= dest_len) {
						warning ("sanitize_string: "
							 "src string too long "
							 "(for escaped colon, "
							 "backslash, period, "
							 "or non-printable "
							 "character)", -1);
						return 1;
					}
					sprintf (temp + j, "\\%03o", src[i+1]);
					j += 4;
					i++;
				} else {
					if (j + 1 >= dest_len) {
						warning ("sanitize_string: "
							 "src string too long "
							 "(for escaped "
							 "printable char)", -1);
						return 1;
					}
					temp[j] = src[i+1];
					j++;
					i++;
				}
			} else {
				if (i + 3 < src_len && isdigit (src[i+2]) &&
				    isdigit (src[i+3])) {
					int num;
					num = (src[i+1] - '0') * 100 +
					      (src[i+2] - '0') * 10 +
					      (src[i+3] - '0');
					if (num > 255) {
						warning ("sanitize_string: "
							 "escaped decimal "
							 "number too large",
							 -1);
						return 1;
					}
					if (isprint (num) && num != ':' &&
					    num != '.' && num != '\\') {
						if (j + 1 >= dest_len) {
							warning (
							"sanitize_string: "
							"src string too long "
							"(for decimal-escaped "
							"printable char)", -1);
							return 1;
						}
						temp[j] = src[i+1];
						j++;
						i++;
					} else {
						if (j + 4 >= dest_len) {
							warning (
							"sanitize_string: "
							"src string too long "
							"(for decimal-escaped "
							"non-printable char or "
							"colon, backslash, "
							"or period)", -1);
							return 1;
						}
						sprintf (temp + j,
							 "\\%03o", num);
						j += 4;
						i += 3;
					}
				} else {
					warning ("sanitize_string: malformed "
						 "escaped decimal sequence",
						 -1);
					return 1;
				}
			}
		} else {
			if (j + 4 >= dest_len) {
				warning ("sanitize_string: src string too "
					 "long (for non-printable char or "
					 "colon)", -1);
				return 1;
			}
			sprintf (temp + j, "\\%03o", src[i]);
			j += 4;

		}
		temp[j] = '\0';
	}

	strcpy (dest, temp);
	return 0;
}

/* get_unescaped_length: returns the true length of string (in other words,
 * \xxx octal sequences only count as one character).  can only be
 * called on strings that have produced by sanitize_string. */
int get_unescaped_length (const char *string)
{
	int i, len;
	if (!string) return 0;
	for (i = 0, len = 0; string[i] != '\0'; i++, len++) {
		if (string[i] == '\\') i += 3;
	}
	return len;
}

/* is_within_origin: returns 1 if domain name falls within domain origin
 * and 0 otherwise. */
int is_within_origin (const char *name, const char *origin, int origin_len)
{
	int name_len;

	if (!name || !origin || origin_len <= 0) return 0;
	name_len = strlen (name);
	if (origin_len > name_len) return 0;
	return (!strcasecmp (origin, name + name_len - origin_len));
}

/* qualify_domain: given domain name (in BIND format) and domain origin
 * (which has already been passed through sanitize_string), constructs a
 * fully-qualified domain name and copies it to dest.  dest MUST be
 * DOMAIN_STR_LEN characters in length.  name and origin can not both be
 * null or empty.  trailing periods are removed.  a temporary string is
 * used, so dest can point to memory contained in either name or origin.  0
 * is returned on success, and 1 otherwise. */
int qualify_domain (char *dest, const char *name, const char *origin)
{
	char temp[DOMAIN_STR_LEN] = "", sname[DOMAIN_STR_LEN] = "", *ptr;
	int name_len, name_real_len, origin_len;

	if (!dest) {
		warning ("qualify_domain: missing dest string", -1);
		return 1;
	}

	if (sanitize_string (sname, DOMAIN_STR_LEN, name)) {
		warning ("qualify_domain: unable to sanitize name", -1);
		return 1;
	}

	if (sname[0] != '\0') {
		if (sname[0] == '.' && sname[1] != '\0') {
			warning ("qualify_domain: empty label", -1);
			return 1;
		}
		/* make sure domain doesn't have two dots in a row */
		ptr = sname;
		while ((ptr = strstr (ptr, ".."))) {
			if (ptr - 4 < sname || strncmp (ptr - 4, "\\134", 4)) {
				warning ("qualify_domain: empty label", -1);
				return 1;
			}
			ptr++;
		}
		if (!strcmp (sname, "@")) {
			if (!origin || origin[0] == '\0') {
				warning ("qualify_domain: name is '@', "
					 "origin is missing", -1);
				return 1;
			}
			origin_len = get_unescaped_length (origin);
			if (origin_len > DOMAIN_LEN) {
				warning ("qualify_domain: origin is "
					 "too long", -1);
				return 1;
			}
			strcpy (temp, origin);
		} else {
			name_len = get_unescaped_length (sname);
			name_real_len = strlen (sname);
			if (sname[name_real_len-1] == '.') {
				if (name_len > DOMAIN_LEN) {
					warning ("qualify_domain: fully-"
						 "qualified name is too "
						 "long", -1);
					return 1;
				}
				strcpy (temp, sname);
			} else {
				if (!origin || origin[0] == '\0') {
					warning ("qualify_domain: name is not "
						 "fully qualified and origin "
						 "is missing", -1);
					return 1;
				}
				if (!strcmp (origin, ".")) {
					if (name_len + 1 > DOMAIN_LEN) {
						warning ("qualify_domain: "
							 "name is too "
							 "long", -1);
						return 1;
					}
					strcpy (temp, sname);
					temp[name_real_len] = '.';
					temp[name_real_len+1] = '\0';
				} else {
					origin_len =
						get_unescaped_length (origin);
					if (name_len + 1 +
					    origin_len > DOMAIN_LEN) {
						warning ("qualify_domain: "
							 "name plus origin "
							 "is too long", -1);
						return 1;
					}
					strcpy (temp, sname);
					temp[name_real_len] = '.';
					strcpy (temp + name_real_len + 1,
						origin);
				}
			}
		}
	} else {
		if (!origin || origin[0] == '\0') {
			warning ("name and origin are both empty "
				 "or missing", -1);
			return 1;
		}
		origin_len = get_unescaped_length (origin);
		if (origin_len >= DOMAIN_LEN) {
			warning ("origin is too long", -1);
			return 1;
		}
		strcpy (temp, origin);
	}

	strcpy (dest, temp);
	return 0;
}

/* str_to_uint: converts the given string into an unsigned integer.  if
 * allow_time_fmt is set, allows BIND time-format strings such as
 * "2w1d2h5m6s".  does not check for overflow.  returns the converted
 * number, and puts 0 into the integer pointed at by ret on success and 1
 * otherwise. */
unsigned int str_to_uint (const char *string, int allow_time_fmt, int *ret)
{
	int in_time_fmt = 0, in_part = 0;
	unsigned int total = 0, part = 0;

	if (!string || *string == '\0') {
		warning ("str_to_uint: NULL or empty string", -1);
		*ret = 1;
		return 0;
	}

	for (; *string != '\0'; string++) {
		if (*string >= '0' && *string <= '9') {
			if (!in_part) in_part = 1;
			part *= 10;
			part += *string - '0';
		} else {
			if (!allow_time_fmt || !in_part) {
				/* don't print a warning here, since this
				 * function is also used to test if strings
				 * are TTLs */
				*ret = 1;
				return 0;
			}
			if (!in_time_fmt) in_time_fmt = 1;
			/* we actually want to overflow here if necessary,
			 * because BIND does too... */
			if (*string == 'w' || *string == 'W') {
				total += part * 86400 * 7;
			} else if (*string == 'd' || *string == 'D') {
				total += part * 86400;
			} else if (*string == 'h' || *string == 'H') {
				total += part * 60 * 60;
			} else if (*string == 'm' || *string == 'M') {
				total += part * 60;
			} else if (*string == 's' || *string == 'S') {
				total += part;
			} else {
				*ret = 1;
				return 0;
			}
			part = 0;
			in_part = 0;
		}
	}
	if (in_time_fmt && in_part) {
		warning ("str_to_uint: unfinished time string", -1);
		*ret = 1;
		return 0;
	}
	if (!in_time_fmt) total = part;

	*ret = 0;
	return total;
}

/* sanitize_ip: takes the dotted-decimal ip address in src and turns it
 * into a nicely-formatted ip address if possible.  dest must be 16
 * characters (or more).  things like 127.00000.0.1 are okay, but strings
 * with out-of-bounds octets are rejected.  returns 0 on success and 1
 * otherwise. */
int sanitize_ip (char *dest, const char *src) {

	char *dot;
	int i, total;

	if (!src) return 1;
	for (i = 0; i < 4; i++) {
		if (i < 3) dot = strchr (src, '.');
		else for (; *dot != '\0'; dot++);
		if (!dot || dot == src) return 1;
		for (total = 0; src < dot; src++) {
			if (*src < '0' || *src > '9') return 1;
			total *= 10;
			total += *src - '0';
		}
		if (total > 255) return 1;
		sprintf (dest, "%d", total);
		for (; *dest != '\0'; dest++);
		if (i < 3) *dest++ = '.';
		src = dot + 1;
	}
	return 0;
}

/* main: */
int main (int argc, char **argv)
{
	char line[LINE_LEN];
	char cur_origin[DOMAIN_STR_LEN] = "\0";
	char origin[DOMAIN_STR_LEN] = "\0";
	char *blank_token = " ";
	unsigned int ttl = DEFAULT_TTL;
	int line_num = 1, origin_len;
	int fd;

	if (argc != 4) {
		fprintf (stderr, "bind-to-tinydns: usage: bind-to-tinydns "
			 "<origin> <output file> <temp file>\n");
		exit (1);
	}
	if (qualify_domain (origin, argv[1], ".")) {
		fprintf (stderr, "fatal: unable to qualify initial origin\n");
		exit (1);
	}
	origin_len = strlen (origin);
	strcpy (cur_origin, origin);
	filename = argv[3];
	if ((fd = open (filename, O_WRONLY | O_CREAT | O_EXCL, 0644)) == -1) {
		fprintf (stderr, "fatal: unable to create temp file: %s\n",
			 strerror (errno));
		exit (1);
	}
	if (!(file = fdopen (fd, "w"))) {
		fprintf (stderr, "fatal: unable to create file stream: %s\n",
			 strerror (errno));
		exit (1);
	}

	/* iterate over each entry */
	while (fgets (line, LINE_LEN, stdin)) {

		int in_doublequote = 0, paren_level = 0;
		int in_quote = 0, set_in_quote = 0, in_txt = 0;
		int i = 0, len, start_line_num, ret;
		char *token[MAX_TOKENS];
		int num_tokens = 0, in_token = 0, found_nonblank_token = 0;

		start_line_num = line_num;

		/* iterate over each line in the entry */
		do {
			len = i + strlen (line + i);
			if (len + 1 >= LINE_LEN)
				fatal ("entry too long", start_line_num);

			/* tokenize the input and look for obvious syntax
			 * errors */
			for (; i < len; i++) {

				if (set_in_quote) {
					in_quote = 1;
					set_in_quote = 0;
				}

				if (line[i] == '\\' && !in_quote) {
					set_in_quote = 1;
				} else if (in_quote && line[i] != '\n') {
					in_quote = 0;
					continue;
				}

				if (in_doublequote && line[i] != '"') {
					continue;
				}

				if (line[i] == ';') {
					line[i] = '\0';
					in_token = 0;
					break;
				} else if (line[i] == '(') {
					line[i] = '\0';
					in_token = 0;
					if (++paren_level > MAX_PAREN)
						fatal ("too many nested "
						       "parentheses",
						       start_line_num);
				} else if (line[i] == ')') {
					line[i] = '\0';
					in_token = 0;
					paren_level--;
					if (paren_level < 0)
						fatal ("missing opening "
						       "parenthesis",
							start_line_num);
				} else if (line[i] == '"') {
					line[i] = '\0';
					if (in_doublequote) {
						in_token = 0;
					} else {
						if (!in_txt) {
						if (num_tokens == 0 ||
						    strcasecmp (
						      token[num_tokens-1],
						      "txt"))
							fatal ("improper use "
							"of double-quotes "
							"(can only be used "
							"for TXT rdata)",
							start_line_num);
						in_txt = 1;
						}
						token[num_tokens] =
							line + i + 1;
						num_tokens++;
						in_token = 1;
					}
					in_doublequote = !in_doublequote;
				} else if ((line[i] == ' ' ||
					    line[i] == '\t')) {
					if (i == 0) {
						token[num_tokens] = blank_token;
						num_tokens++;
					} else {
						line[i] = '\0';
						in_token = 0;
					}
				} else if (line[i] == '\n' || line[i] == '\r') {
					line[i] = '\0';
					in_token = 0;
				} else if (!in_token) {
					if (num_tokens >= MAX_TOKENS)
						fatal ("too many tokens "
						"in RR", start_line_num);
					token[num_tokens] = line + i;
					in_token = 1;
					num_tokens++;
					found_nonblank_token = 1;
				}
			}

			if (in_quote) fatal ("open backslash quote at end "
					     "of line", start_line_num);
			if (in_doublequote) fatal ("open doublequotes at end "
					     "of line", start_line_num);

			line_num++;

		} while (paren_level &&
			 fgets (line + i, LINE_LEN - i, stdin));

		if (paren_level) fatal ("open parentheses at end of file",
			start_line_num);

		/* skip empty or comment-only lines */
		if (!num_tokens || !found_nonblank_token) continue;

#if 0
		/* debug token-parsing code */
		for (i = 0; i < num_tokens; i++) {
			printf ("<%s> ", token[i]);
		}
		printf ("\n\n");
#endif

		/* handle directives */
		if (!strcasecmp (token[0], "$origin")) {
			if (num_tokens != 2)
				fatal ("$ORIGIN directive has wrong number "
				       "of arguments", start_line_num);
			if (qualify_domain (cur_origin, token[1], cur_origin))
				fatal ("choked on domain name in $ORIGIN "
				       "statement", start_line_num);
		} else if (!strcasecmp (token[0], "$ttl")) {
			if (num_tokens != 2)
				fatal ("$TTL directive has wrong number of "
				       "arguments", start_line_num);
			ttl = str_to_uint (token[1], 1, &ret);
			if (ret || ttl > 2147483646)
				fatal ("invalid $TTL value", start_line_num);
		} else if (!strcasecmp (token[0], "$include")) {
			fatal ("sorry, $INCLUDE directive is unimplemented",
			       start_line_num);
		} else if (!strcasecmp (token[0], "$generate")) {
			fatal ("sorry, $GENERATE directive is unimplemented",
			       start_line_num);
		} else if (token[0][0] == '$') {
			fatal ("unknown $ directive", start_line_num);
		/* handle records */
		} else {
			int next;
			unsigned int local_ttl, temp_ttl;
			static char owner[DOMAIN_STR_LEN] = "\0";
			static char rdomain[DOMAIN_STR_LEN] = "\0";

			if (num_tokens < 3)
				fatal ("RR does not have enough tokens",
				       start_line_num);

			if (strcmp (token[0], " ")) {
				if (qualify_domain (owner, token[0],
						    cur_origin))
					fatal ("choked on owner name in "
					       "RR", start_line_num);
				if (!is_within_origin (owner, origin,
						       origin_len)) {
					warning ("ignoring out-of-zone data",
						 start_line_num);
					continue;
				}
			} else {
				if (owner[0] == '\0') {
					fatal ("RR tried to inherit "
					       "owner from previous record, "
					       "but there was no previous "
					       "RR", start_line_num);
				}
			}

			local_ttl = ttl;

			/* process ttl and/or class, and find where type
			 * token is.  whose brilliant idea was it to let
			 * these two come in either order? */
			next = 1;
			temp_ttl = str_to_uint (token[1], 1, &ret);
			if (!ret) {
				if (local_ttl > 2147483646)
					fatal ("invalid TTL in RR",
					       start_line_num);
				local_ttl = temp_ttl;
				if (!strcasecmp (token[2], "IN")) {
					next = 3;
				} else {
					next = 2;
				}
			} else if (!strcasecmp (token[1], "IN")) {
				temp_ttl = str_to_uint (token[2], 1, &ret);
				if (!ret) {
					if (local_ttl > 2147483646)
						fatal ("invalid TTL in RR",
						       start_line_num);
					local_ttl = temp_ttl;
					next = 3;
				} else {
					next = 2;
				}
			}

			/* SOA */
			if (!strcasecmp (token[next], "SOA")) {
				char rname[DOMAIN_STR_LEN];
				unsigned int serial, refresh, retry;
				unsigned int expire, minimum;
				if (num_tokens - next - 1 == 2)
					fatal ("wrong number of tokens in "
					       "SOA RDATA (perhaps an opening "
					       "parenthesis is on the next "
					       "line instead of this one?)",
					       start_line_num);
				if (num_tokens - next - 1 != 7)
					fatal ("wrong number of tokens in "
					       "SOA RDATA", start_line_num);
				if (qualify_domain (rdomain, token[next+1],
						    cur_origin))
					fatal ("choked on MNAME in SOA "
					       "RDATA", start_line_num);
				if (qualify_domain (rname, token[next+2],
						    cur_origin))
					fatal ("choked on RNAME in SOA "
					       "RDATA", start_line_num);
				serial = str_to_uint (token[next+3], 0, &ret);
				if (ret) fatal ("invalid SERIAL in SOA RDATA",
						start_line_num);
				refresh = str_to_uint (token[next+4], 1, &ret);
				if (ret) fatal ("invalid REFRESH in SOA RDATA",
						start_line_num);
				retry = str_to_uint (token[next+5], 1, &ret);
				if (ret) fatal ("invalid RETRY in SOA RDATA",
						start_line_num);
				expire = str_to_uint (token[next+6], 1, &ret);
				if (ret) fatal ("invalid EXPIRE in SOA RDATA",
						start_line_num);
				minimum = str_to_uint (token[next+7], 1, &ret);
				if (ret) fatal ("invalid MINIMUM in SOA RDATA",
						start_line_num);
				fprintf (file, "Z%s:%s:%s:%u:%u:%u:%u:%u\n",
					 owner, rdomain, rname, serial,
					 refresh, retry, expire, minimum);
			/* NS */
			} else if (!strcasecmp (token[next], "NS")) {
				if (num_tokens - next - 1 != 1)
					fatal ("wrong number of tokens in NS "
					       "RDATA", start_line_num);
				if (qualify_domain (rdomain, token[next+1],
						    cur_origin))
					fatal ("choked on domain name in NS "
					       "RDATA", start_line_num);
				fprintf (file, "&%s::%s:%d\n", owner,
					 rdomain, local_ttl);
			/* MX */
			} else if (!strcasecmp (token[next], "MX")) {
				unsigned int priority;
				if (num_tokens - next - 1 != 2)
					fatal ("wrong number of tokens in MX "
					       "RDATA", start_line_num);
				priority = str_to_uint (token[next+1], 0, &ret);
				if (ret || priority > 65535)
					fatal ("invalid priority in MX "
					       "RDATA", start_line_num);
				if (qualify_domain (rdomain, token[next+2],
						    cur_origin))
					fatal ("choked on domain name in MX "
					       "RDATA", start_line_num);
				fprintf (file, "@%s::%s:%d:%d\n", owner,
					 rdomain, priority, local_ttl);
			/* A */
			} else if (!strcasecmp (token[next], "A")) {
				char ip[16];
				if (num_tokens - next - 1 != 1)
					fatal ("wrong number of tokens in A "
					       "RDATA", start_line_num);
				if (sanitize_ip (ip, token[next+1]))
					fatal ("invalid IP address in A "
					       "RDATA", start_line_num);
				fprintf (file, "+%s:%s:%d\n", owner,
					 ip, local_ttl);
			/* CNAME */
			} else if (!strcasecmp (token[next], "CNAME")) {
				if (num_tokens - next - 1 != 1)
					fatal ("wrong number of tokens "
					       "in CNAME RDATA",
					       start_line_num);
				if (qualify_domain (rdomain, token[next+1],
						    cur_origin))
					fatal ("choked on domain name in CNAME "
					       "RDATA", start_line_num);
				fprintf (file, "C%s:%s:%d\n", owner,
					 rdomain, local_ttl);
			/* PTR */
			} else if (!strcasecmp (token[next], "PTR")) {
				if (num_tokens - next - 1 != 1)
					fatal ("wrong number of tokens "
					       "in PTR RDATA", start_line_num);
				if (qualify_domain (rdomain, token[next+1],
						    cur_origin))
					fatal ("choked on domain name in PTR "
					       "RDATA", start_line_num);
				fprintf (file, "^%s:%s:%d\n", owner,
					 rdomain, local_ttl);
			/* TXT */
			} else if (!strcasecmp (token[next], "TXT")) {
				char txt_rdata[LINE_LEN] = "\0";
				int txt_len;
				if (num_tokens - next - 1 < 1)
					fatal ("too few tokens in TXT "
					       "RDATA", start_line_num);
				fprintf (file, ":%s:16:", owner);
				for (i = next + 1; i < num_tokens; i++) {
					if (sanitize_string (txt_rdata,
					    LINE_LEN, token[i]))
						fatal ("choked while "
						"sanitizing TXT RDATA",
						start_line_num);
					txt_len = get_unescaped_length (
							txt_rdata);
					if (txt_len > 255)
						fatal ("character string "
						       "in TXT RDATA is too "
						       "long", start_line_num);
					fprintf (file, "\\%03o%s", txt_len,
						 txt_rdata);
				}
				fprintf (file, ":%d\n", local_ttl);
			/* SRV */
			} else if (!strcasecmp (token[next], "SRV")) {
				unsigned int priority, weight, port;
				if (num_tokens - next - 1 != 4)
					fatal ("wrong number of tokens "
					       "in SRV RDATA", start_line_num);
				priority = str_to_uint (token[next+1], 0, &ret);
				if (ret || priority > 65535)
					fatal ("invalid priority in SRV RDATA",
					       start_line_num);
				weight = str_to_uint (token[next+2], 0, &ret);
				if (ret || weight > 65535)
					fatal ("invalid weight in SRV RDATA",
					       start_line_num);
				port = str_to_uint (token[next+3], 0, &ret);
				if (ret || port > 65535)
					fatal ("invalid port in SRV RDATA",
					       start_line_num);
				if (qualify_domain (rdomain, token[next+4],
						    cur_origin))
					fatal ("choked on domain name in SRV "
					       "RDATA", start_line_num);
				fprintf (file, ":%s:33:\\%03o\\%03o"
					 "\\%03o\\%03o\\%03o\\%03o\\%03o%s"
					 ":%d\n", owner, priority / 256,
					 priority % 256, weight / 256,
					 weight % 256, port / 256, port % 256,
					 get_unescaped_length (rdomain),
					 rdomain, local_ttl);
			/* other */
			} else {
				fatal ("unknown RR type", start_line_num);
			}
		}
	}

	if (fclose (file)) {
		fprintf (stderr, "fatal: unable to close temp file: %s\n",
			 strerror (errno));
		exit (1);
	}
	if (rename (filename, argv[2])) {
		fprintf (stderr, "fatal: unable to rename temp file: %s\n",
			 strerror (errno));
		if (unlink (filename)) {
			fprintf (stderr, "unable to unlink temp file: %s\n",
				 strerror (errno));
		}
		exit (1);
	}

	return 0;
}
