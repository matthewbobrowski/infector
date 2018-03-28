/**                                                                             
 * Copyright (C) 2018 Matthew Bobrowski                                         
 *                                                                               
 * This program is free software: you can redistribute it and/or modify         
 * under the terms of the GNU General Public License as published by            
 * the Free Software Foundation, either version 3 of the License, or            
 * (at your option) any later version.                                          
 *                                                                               
 * This program is distributed in the hope that it will be useful,              
 * but WITHOUT ANY WARRANTY; without even the implied warranty of               
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                
 * GNU General Public License for more details.                                 
 *                                        
 * You should have received a copy of the GNU General Public License             
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.       
 */

#include <stdio.h>
#include <unistd.h>

static const unsigned int seconds = 5;

int
main(int argc, char **argv)
{
	for (;;) {
		printf("Not infected.\n");
		sleep(seconds);
	}	
}
