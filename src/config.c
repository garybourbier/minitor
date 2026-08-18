/*
Copyright (C) 2022 Triple Layer Development Inc.

Minitor is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

Minitor is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "../include/config.h"

#ifdef MINITOR_CHUTNEY
  int tor_authorities_count = 3;
#else
  int tor_authorities_count = 6;
#endif

const char* tor_authorities[] =
{
#ifdef MINITOR_CHUTNEY
MINITOR_CHUTNEY_ADDRESS_STR " dirport=7000",
MINITOR_CHUTNEY_ADDRESS_STR " dirport=7001",
MINITOR_CHUTNEY_ADDRESS_STR " dirport=7002"
#else
/* Updated 2026-08-15 — verified from live Tor consensus */
"199.58.81.140 dirport=80",   /* longclaw  — official DA */
"204.13.164.118 dirport=80",  /* bastet    — official DA */
"131.188.40.189 dirport=80",  /* gabelmoo  — official DA */
"171.25.193.9 dirport=443",   /* maatuska  — official DA, HTTP on 443 */
"195.154.164.243 dirport=80", /* fallback  — verified 2026-08-15 */
"217.196.147.77 dirport=80",  /* fallback  — verified 2026-08-15 */
#endif
};
