#
# Clear Designate database
#
use designate
truncate records;
delete from domains;	
	
use powerdns
truncate records;
delete from domains;	
	

use geodns
delete from geoips;
delete from records;
delete from domains;		
