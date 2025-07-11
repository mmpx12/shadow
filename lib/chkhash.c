#include <regex.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>


/*
 * match_regex - return true if mathch, false if not
 */
bool 
match_regex(const char *pattern, const char *string) 
{
	regex_t regex;
	if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
		return false;
	}	

	int result = regexec(&regex, string, 0, NULL, 0);
	regfree(&regex);
	return result == 0;
}

/*
 * is_valid_hash - check if the given string is a valid password hash
 *
 * Returns true if the string appears to be a valid hash, false otherwise.
 */
bool 
is_valid_hash(const char *hash) 
{
	if (hash == NULL) {
		return false;
	}

	// Minimum length for DES
	if (strlen(hash) < 13) {
		return false;
	}

	// DES: exactly 13 characters from [A-Za-z0-9./]
	if (strlen(hash) == 13 && match_regex("^[A-Za-z0-9./]{13}$", hash)) {
		return true;
	}

	// MD5: $1$ + salt + $ + 22-char hash
	if (match_regex("^\\$1\\$[A-Za-z0-9./]{1,16}\\$[A-Za-z0-9./]{22}$", hash)) {
		return true;
	}

	// SHA-256: $5$ + salt + $ + 43-char hash
	if (match_regex("^\\$5\\$[A-Za-z0-9./]{1,16}\\$[A-Za-z0-9./]{43}$", hash)) {
        	return true;
	}

	// SHA-512: $6$ + salt + $ + 86-char hash
	if (match_regex("^\\$6\\$[A-Za-z0-9./]{1,16}\\$[A-Za-z0-9./]{86}$", hash)) {
		return true;
	}

	// Bcrypt: $2[abzy]$ + 2-digit cost + $ + 53-char hash
	if (match_regex("^\\$2[aby]\\$[0-9]{2}\\$[A-Za-z0-9./]{53}$", hash)) {
		return true;
	}

	// Yescrypt: $y$ + something
	if (match_regex("^\\$y\\$.*", hash)) {
		return true;
	}

	// Not a valid hash
	return false;
}

