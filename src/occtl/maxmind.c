/*
 * Copyright (c) 2018 Red Hat, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *   Martin Sehnoutka <msehnout@redhat.com>
 *   Nikos Mavrogiannopoulos
 */

#include "config.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "geoip.h"

#ifdef HAVE_MAXMIND
#include <maxminddb.h>

#ifndef MAXMINDDB_LOCATION_COUNTRY
#define MAXMINDDB_LOCATION_COUNTRY "/usr/share/GeoIP/dbip-country-lite.mmdb"
#endif

#ifndef MAXMINDDB_LOCATION_CITY
#define MAXMINDDB_LOCATION_CITY "/usr/share/GeoIP/dbip-city-lite.mmdb"
#endif

static bool get_entry_data(MMDB_entry_s *entry, const char *const *path,
			   uint32_t type, MMDB_entry_data_s *data)
{
	return (MMDB_aget_value(entry, data, path) == MMDB_SUCCESS) &&
	       data->has_data && (data->type == type);
}

/* false when the record has no string at path */
static bool get_string(MMDB_entry_s *entry, const char *const *path, char *buf,
		       size_t buf_size)
{
	MMDB_entry_data_s data;
	size_t len;

	if (!get_entry_data(entry, path, MMDB_DATA_TYPE_UTF8_STRING, &data))
		return false;

	/* MaxMind DB strings are not NUL-terminated */
	len = (data.data_size < buf_size) ? data.data_size : (buf_size - 1);
	memcpy(buf, data.utf8_string, len);
	buf[len] = 0;
	return true;
}

/* On success the caller must close mmdb */
static int lookup(const char *file, const char *ip, MMDB_s *mmdb,
		  MMDB_lookup_result_s *result)
{
	int gai_error, mmdb_error;

	if (MMDB_open(file, MMDB_MODE_MMAP, mmdb) != MMDB_SUCCESS)
		return -1;

	/* mmdb_error is not set when gai_error is */
	*result = MMDB_lookup_string(mmdb, ip, &gai_error, &mmdb_error);
	if ((gai_error != 0) || (mmdb_error != MMDB_SUCCESS) ||
	    !result->found_entry) {
		MMDB_close(mmdb);
		return -1;
	}

	return 0;
}

/* A missing database or record is not an error: the location is then
 * "unknown" or lacks the values that record would provide */
char *geo_lookup(const char *ip, char *buf, unsigned int buf_size)
{
	static const char *const country_keys[] = { "country",
						    "represented_country",
						    "registered_country" };
	static const char *const city_path[] = { "city", "names", "en", NULL };
	static const char *const latitude_path[] = { "location", "latitude",
						     NULL };
	static const char *const longitude_path[] = { "location", "longitude",
						      NULL };
	MMDB_s mmdb;
	MMDB_lookup_result_s result;
	MMDB_entry_data_s latitude, longitude;
	char country[128] = "", city[128] = "", coord[64] = "";
	unsigned int i, len;

	if (lookup(MAXMINDDB_LOCATION_COUNTRY, ip, &mmdb, &result) == 0) {
		for (i = 0;
		     (i < (sizeof(country_keys) / sizeof(country_keys[0]))) &&
		     (country[0] == 0);
		     i++) {
			const char *const name_path[] = { country_keys[i],
							  "names", "en", NULL };
			const char *const code_path[] = { country_keys[i],
							  "iso_code", NULL };

			if (!get_string(&result.entry, name_path, country,
					sizeof(country)))
				get_string(&result.entry, code_path, country,
					   sizeof(country));
		}
		MMDB_close(&mmdb);
	}

	if (lookup(MAXMINDDB_LOCATION_CITY, ip, &mmdb, &result) == 0) {
		get_string(&result.entry, city_path, city, sizeof(city));
		if (get_entry_data(&result.entry, latitude_path,
				   MMDB_DATA_TYPE_DOUBLE, &latitude) &&
		    get_entry_data(&result.entry, longitude_path,
				   MMDB_DATA_TYPE_DOUBLE, &longitude))
			snprintf(coord, sizeof(coord), "%f,%f",
				 latitude.double_value, longitude.double_value);
		MMDB_close(&mmdb);
	}

	if (country[0] == 0)
		return "unknown";

	if (city[0] != 0)
		snprintf(buf, buf_size, "%s, %s", city, country);
	else
		snprintf(buf, buf_size, "%s", country);

	len = strlen(buf);
	if ((coord[0] != 0) && (len < buf_size))
		snprintf(buf + len, buf_size - len, " (%s)", coord);

	return buf;
}

#else
char *geo_lookup(const char *ip, char *buf, unsigned int buf_size)
{
	return "unknown";
}
#endif /* HAVE_MAXMIND */
