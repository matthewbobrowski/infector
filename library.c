/*
 * Author: Matthew Bobrowski <mbobrowski@mbobrowski.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
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

static long 
evil()
{
	char value[10];

	value[0] = 'I';
	value[1] = 'n';
	value[2] = 'f';
	value[3] = 'e';
	value[4] = 'c';
	value[5] = 't';
	value[6] = 'e';
	value[7] = 'd';
	value[8] = '\0';

	long (*original)(char *buffer) = 0x7fffffffffff;
	original(value);
}
