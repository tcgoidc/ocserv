/*
 * Copyright (C) 2026 Nikos Mavrogiannopoulos
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* Checks occtl's geo_lookup() against the databases that mkmmdb.py
 * generates from geo-country.json and geo-city.json (REQ-OCCTL-CLI-012) */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/occtl/geoip.h"

static const struct {
	const char *ip;
	const char *location;
} tests[] = {
	{ "192.0.2.5", "Athens, Greece (37.984200,23.735300)" },
	{ "2001:db8::1", "Berlin, Germany (52.519600,13.406900)" },
	/* only a registered_country */
	{ "198.51.100.5", "United States (37.751000,-97.822000)" },
	/* the represented_country takes precedence over the registered one */
	{ "198.51.100.130", "United States (37.751000,-97.822000)" },
	/* no country of any kind */
	{ "198.51.100.200", "unknown" },
	/* not in the databases */
	{ "203.0.113.1", "unknown" },
	{ "not-an-address", "unknown" },
};

int main(void)
{
	char buf[256];
	const char *location;
	unsigned int i;
	int failed = 0;

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		location = geo_lookup(tests[i].ip, buf, sizeof(buf));
		if (strcmp(location, tests[i].location) != 0) {
			fprintf(stderr,
				"FAIL: geo_lookup(%s): expected '%s', got '%s'\n",
				tests[i].ip, tests[i].location, location);
			failed = 1;
		}
	}

	return failed;
}
