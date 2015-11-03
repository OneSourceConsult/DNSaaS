## Using the API
__This section provide information about CRUD operations regarding domains and records using the DNSaaS CLI, or via CURL command.__
  
### Get a valid token

___Parameters:___

* _User Name ;_
* _User Password ;_
* _Tenant Name ;_

__Using the DNSaaS client:__

	DNSaaSClient.getTokenId('<UserName>','<Password>','<TenantName>')
	
__Using Curl__

	curl -X GET -H 'Accept: application/json' -H 'Content-Type: application/json' "http://DNSaaS_API_IP_Address>:8080/credentials" -d '{"user": "User name", "password": "User Password", "tenant": "Tenant name"}'

___Returns:___

* _Jason list containing the token ID._

## Section regarding domain operations:

### Create a domain

___Parameters:___

* _Domain name, __ex: domain.com__ ;_
* _Domain admin email address ;_
* _Time to live, ttl (Integer);_
* _Token ID ;_

__Using the DNSaaS client:__

	DNSaaSClient.createDomain('<Domain name>','<e-mail address>',<ttl>, <tokenID>)
	
__Using Curl__

	curl -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-auth-token: <TokenID>' "http://<DNSaaS_API_IP_Address>:8080/domains" -d '{"name": "<domain_name>", "<ttl>": <Integer ttl>, "email": "<e-mail address>"}'
	
___Returns:___

* __1__ _for success or in case of failure, the description of the error._

### Get a domain

___Parameters:___

* _Domain name ;_
* _Token Id ;_

__Using the DNSaaS client:__

	DNSaaSClient.getDomain('<domain_name>',<tokenID>)

__Using Curl__
	
	curl -X GET -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-auth-token: <TokenID>' "http://<DNSaaS_API_IP_Address>:8080/domains" -d '{"domain_name": "<domain_name>"}'

___Returns:___

* _A list of the record information._

### Update a domain

___Parameters:___

* _Domain name_
* _Parameter to update, 'ttl', 'email' or 'description';_
* _Time to live, ttl (interger);_
* _Token ID ;_

__Using the DNSaaS client:__

	DNSaaSClient.updateDomain('<domain_name>','<parameter_to_update>',<value to update>,<tokenID>)
	
__Using Curl__

	curl -X PUT -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-auth-token: <TokenID>' "http://<DNSaaS_API_IP_Address>:8080/domains" -d '{"domain_name": "<domain_name>", "parameter_to_update": "<ttl, e-mail or description>", "data":<value_to_update>}'
	
___Returns:___

* __1__ _for success or in case of failure, the description of the error._

### Delete a domain

___Parameters:___

* _Domain name ;_
* _Token Id ;_

__Using the DNSaaS client:__

	DNSaaSClient.deleteDomain('<domain_name>',tokenID)
	
__Using Curl__

	curl -X DELETE -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-auth-token: <TokenID>' "http://<DNSaaS_API_IP_Address>:8080/domains" -d '{"domain_name": "<domain_name>"}'
	
___Returns:___

* __1__ _for success or in case of failure, the description of the error._

## Section regarding record operations:

__CRUD method reference for records type: 'A', 'AAAA', 'TXT', 'MX', 'PTR', 'SRV', 'NS', 'CNAME', 'SPF', 'SSHFP', 'NAPTR'__

### Create a record type A

___Parameters:___

* _Domain name ;_
* _Record Name ;_
* _Record type, __A__ ;_
* _Data, the Ip address for the record ;_
* _TokenId ;_


__Using the DNSaaS client:__


	DNSaaSClient.createRecord('<domain_name>','<record_name>','<record_type>,'<record_data>',tokenID)

__Using Curl__

	curl -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-auth-token: <TokenID>' "http://<DNSaaS_API_IP_Address>:8080/records" -d '{"domain_name": "<domain_name>", "record_name": "<record_name>", "type": "A", "data":"<record_data>"}'

___Returns:___

* __1__ _for success or in case of failure, the description of the error._
	
### Create a record type AAAA

___Parameters:___

* _Domain name ;_
* _Record Name ;_
* _Record type, __AAAA__;_
* _Data ;_
* _TokenId ;_

__Using the DNSaaS client:__

	DNSaaSClient.createRecord('<domain_name>','<record_name>','<record_type>,'<record_data>',tokenID)
	
__Using Curl__

	curl -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-auth-token: <TokenID>' "http://<DNSaaS_API_IP_Address>:8080/records" -d '{"domain_name": "<domain_name>", "record_name": "<record_name>", "type": "AAAA", "data":"<record_data>"}'
	
___Returns:___

* __1__ _for success or in case of failure, the description of the error._

### Create a record type MX

___Parameters:___

* _Domain name ;_
* _Record Name, by default is null;_
* _Record type, __MX__;_
* _Data, the mail record information, EX: mail.example.com ;_
* _TokenId;_
* _Priority goes as argument, integer;_

__Using the DNSaaS client:__


	DNSaaSClient.createRecord('<domain_name>','<record_name>','<record_type>,'<record_data>',tokenId=tokenID, <priority>)
	
__Using Curl:__

	curl -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-auth-token: <TokenID>' "http://<DNSaaS_API_IP_Address>:8080/records" -d '{"domain_name": "<domain_name>", "record_name": """,, "type": "MX", "data":"mail.example.com", "priority":<priority>}'

___Returns:___

* __1__ _for success or in case of failure, the description of the error._

### Create a record type CNAME

___Parameters:___

* _Domain name ;_
* _Record Name ;_
* _Record type, __CNAME__;_
* _Data;_

__Using the DNSaaS client:__

	DNSaaSClient.createRecord('<domain_name>','<record_name>','<record_type>,'<record_data>',tokenID)

__Using Curl:__

	curl -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-auth-token: <TokenID>' "http://<DNSaaS_API_IP_Address>:8080/records" -d '{"domain_name": "<domain_name>", "record_name": "<record_name>", "type": "CNAME", "data":"<record_data>"}'
	
___Returns:___

* __1__ _for success or in case of failure, the description of the error._

### Create a record type TXT

___Parameters:___

* _Domain name ;_
* _Record Name ;_
* _Record type, __TXT__ ;_
* _Data ;_

__Using the DNSaaS client:__

	DNSaaSClient.createRecord('<domain_name>','<record_name>','<record_type>,'<record_data>',tokenID)

__Using Curl:__

	curl -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-auth-token: <TokenID>' "http://<DNSaaS_API_IP_Address>:8080/records" -d '{"domain_name": "<domain_name>", "record_name": "<record_name>", "type": "TXT", "data":"<record_data>"}'
	
___Returns:___

* __1__ _for success or in case of failure, the description of the error._

### Create a record type SRV

___Parameters:___

* _Domain name ;_
* _Record Name ;_
* _Record type, __SRV__ ;_
* _Data, the mail record information ;_
* _TokenId ;_
* _Priority goes as argument, integer ;_

__Using the DNSaaS client:__

	DNSaaSClient.createRecord('<domain_name>','<record_name>','<record_type>,'<record_data>',tokenId=tokenID, <priority>)

__Using Curl:__

	curl -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-auth-token: <TokenID>' "http://<DNSaaS_API_IP_Address>:8080/records" -d '{"domain_name": "<domain_name>", "record_name": "", "type": "SRV", "data":"mail.example.com", "priority":<priority>}'
	
___Returns:___

* __1__ _for success or in case of failure, the description of the error._

### Create a record type NS

___Parameters:___

* _Domain name ;_
* _Record Name, this parameter for NS record must be null ;_
* _Record type, __NS__ ;_
* _Data, use this parameter to insert the NS record name to be created ;_
* _TokenId ;_

__Using the DNSaaS client:__


	DNSaaSClient.createRecord('<domain_name>','','<record_type>,'<record_data>',tokenID)
	
__Using Curl:__

	curl -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-auth-token: <TokenID>' "http://<DNSaaS_API_IP_Address>:8080/records" -d '{"domain_name": "<domain_name>", "record_name": "<record_name>", "type": "NS", "data":"<EX: ns2"}'
	
___Returns:___

* __1__ _for success or in case of failure, the description of the error._

### Create a record type SFP

___Parameters:___

* _Domain name ;_
* _Record Name, defaults to null ;_
* _Record type, __SPF__ ;_
* _Data ;_
* _TokenId ;_

__Using the DNSaaS client:__


	DNSaaSClient.createRecord('<domain_name>','','<record_type>,'<record_data>',tokenID)

__Using Curl:__

	curl -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-auth-token: <TokenID>' "http://<DNSaaS_API_IP_Address>:8080/records" -d '{"domain_name": "<domain_name>", "record_name": "<defaults to null>", "type": "SFP", "data":"<record_data>"}'
	
___Returns:___

* __1__ _for success or in case of failure, the description of the error._

### Create a record type SSHFP

___Parameters:___

* _Domain name ;_
* _Record Name ;_
* _Record type, __NS__ ;_
* _Data ;_
* _TokenId ;_

__Using the DNSaaS client:__

	DNSaaSClient.createRecord('<domain_name>','record_name','<record_type>,'<record_data>',tokenID)
	
__Using Curl:__

	curl -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-auth-token: <TokenID>' "http://<DNSaaS_API_IP_Address>:8080/records" -d '{"domain_name": "<domain_name>", "record_name": "<record_name>", "type": "SSHFP", "data":"<record_data>"}'

___Returns:___

* __1__ _for success or in case of failure, the description of the error._

### Create a record type NAPTR

___Parameters:___

* _Domain name ;_
* _Record Name ;_
* _Record type, __NAPTR__ ;_
* _Data, __EX: '100 50 \"s\" \"za\" \"\" .'__ ;_
* _TokenId ;_
* _Priority, as argument ;_

__Using the DNSaaS client:__

	DNSaaSClient.createRecord('<domain_name>','<record_name>','<record_type>,'<record_data>',tokenId=tokenID, <priority>)
	
__Using Curl:__

	curl -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-auth-token: <TokenID>' "http://<DNSaaS_API_IP_Address>:8080/records" -d '{"domain_name": "<domain_name>", "record_name": "<record_name>", "type": "NAPTR", "data":"mail.example.com", "priority":<priority>}'

___Returns:___

* __1__ _for success or in case of failure, the description of the error._

### Create a record type PTR

___Parameters:___

* _Domain name, __EX: 4.168.192.in-addr.arpa__ ;_ (create the zone using the createDomain method before creating a PTR record)
* _Record Name, __EX: www.example.com__ ;_
* _Record type, __PTR__ ;_
* _Data, EX: __'1.4.168.192.in-addr.arpa__ ;_
* _TokenId ;_

__Using the DNSaaS client:__

	DNSaaSClient.createRecord('<domain_name>','record_name','<record_type>,'<record_data>',tokenID)

__Using Curl:__

	curl -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-auth-token: <TokenID>' "http://<DNSaaS_API_IP_Address>:8080/records" -d '{"domain_name": "<domain_name>", "record_name": "<record_name>", "type": "PTR", "data":"<record_data>"}'
	
___Returns:___

* __1__ _for success or in case of failure, the description of the error._


### Get a record

___Parameters:___

* _Domain name ;_
* _Record Name ;_
* _Record type ;_
* _TokenId ;_

__Using the DNSaaS client:__

	DNSaaSClient.getRecord('<domain_name>','','<record_type>,'<record_data>',tokenID)
	
__Using Curl:__

	curl -X GET -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-auth-token: <TokenID>' "http://<DNSaaS_API_IP_Address>:8080/records" -d '{"domain_name": "<domain_name>", "record_name": "<record_name>", "type": "<record_type>"}' | python -m json.tool
	
___Returns:___

* _Json list containig the information about the selected record._

### Get all records from a domain

### Get a record

___Parameters:___

* _Domain name ;_
* _Record Name ;_
* _Record type, must be null ;_
* _TokenId ;_

__Using the DNSaaS client:__

	DNSaaSClient.getRecord('<domain_name>','','<record_type>,'<record_data>',tokenID)
	
__Using Curl:__

	curl -X GET -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-auth-token: <TokenID>' "http://<DNSaaS_API_IP_Address>:8080/records" -d '{"domain_name": "<domain_name>", "record_name": "<record_name>", "type": " "}' | python -m json.tool

___Returns:___

* _Json list containing all the records information from the selected domain._

### Update a record

___Parameters:___

* _Domain name ;_
* _Record Name ;_
* _Record type ;_
* _Parameter to update, 'ttl', 'description' or 'data' ;_
* _TokenID ;_

__Using the DNSaaS client:__

		DNSaaSClient.updateRecord('<domain_name>', '<record_name>', '<record_type>', '<parameter_to_update>', '<data>', tokenID)
		
__Using Curl:__

	curl -X PUT -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-auth-token: <TokenID>' "http://<DNSaaS_API_IP_Address>:8080/records" -d '{"domain_name": "<domain_name>", "record_name": "<record_name>", "type": "<record_type>", "parameter_to_update": "<'ttl', 'description' or 'data'>", "data": "<data>"}'
	
___Returns:___

* __1__ _for success or in case of failure, the description of the error._
	


### Delete a record

___Parameters:___

* _Domain name ;_
* _Record Name ;_
* _Record type ;_
* _TokenID ;_

__Using the DNSaaS Client:__

	DNSaaSClient.deleteRecord('<domain_name>','<record_name>','<record_type>',tokenID)
	
__Using Curl:__


	curl -X DELETE -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-auth-token: <TokenID>' "http://<DNSaaS_API_IP_Address>:8080/records" -d '{"domain_name": "<domain_name>","type": "<record_type>", "record_name": "<record_name>"}'

___Returns:___

* __1__ _for success or in case of failure, the description of the error._


## Section regarding GEO record operations:

__GEO DNS CRUD operations method reference.__

###Create a Geo Map for a record

___Parameters:___

* _Record Name ;_
* _Domain Name ;_
* _Geo info, list of Iso codes followed by the record or address to redirect:_
   
   _EX: ["124 IP.Canada.com.","250 France","276 GermanyYoutube","642 Romania","0 default.youtube.com."] ;_ 
   
   _The ISO code 0 means that the information returned by default is the one listed if the ISO code from the country where the dns request is being performed is espcified on the file ;_
	
* _TokenID ;_

__Using the DNSaaS Client:__

	DNSaaSClient.createGeoMap('<record_name>','<domain_name>',<[geoInfo]>,tokenID)

__Using Curl:__

	curl -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-auth-token: <TokenID>' "http://<DNSaaS_API_IP_Address>:8080/geodns" -d '{"record_name": "<record_name>",'domain_name': "<domain_name>", "geoInfo": [geoInfo]}'
	
___Returns:___

* __1__ _for success or in case of failure, the description of the error._


### Get record Geo Map information

___Parameters:___

* _Record Name ;_
* _Domain Name ;_
* _TokenID ;_

__Using the DNSaaS Client:__

	DNSaaSClient.getGeoMap('<record_name>','<domain_name>',tokenID)
	
__Using Curl:__

	curl -X GET -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-auth-token: <TokenID>' "http://<DNSaaS_API_IP_Address>:8080/geodns" -d '{"record_name": "<record_name>",'domain_name': "<domain_name>"}'


___Returns:___

* _Geo Map information regarding the record_


### Append geo code/s to an exiting Geo MAP

___Parameters:___

* _Record Name ;_
* _Domain Name ;_
* _Geo info, list of Iso codes followed by the record or address to redirect:_
	* _EX: ["344 Hong-Kong","528 Netherlands"]_
* _TokenID ;_

__Using the DNSaaS Client:__

	DNSaaSClient.appendGeoMap('<record_name>','<domain_name>',<[GEO Info to append]>,tokenID)
	
	
__Using Curl:__

	curl -X PUT -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-auth-token: <TokenID>' "http://<DNSaaS_API_IP_Address>:8080/geodns" -d '{"record_name": "<record_name>",'domain_name': "<domain_name>", "geoInfo": [GEO Info to append]}'

___Returns:___

* __1__ _for success or in case of failure, the description of the error._


### Delete a Iso code from GeoFile

___Parameters:___

* _Record Name ;_
* _Domain Name ;_
* _Info to remove, as arguments:_
	* _EX: ["344 Hong-Kong","528 Netherlands"]_
* _TokenID ;_
 
__Using the DNSaaS Client:__

	DNSaaSClient.deleteGeoMap('<record_name>','<domain_name>', tokenID, infoToRemove=["344 Hong-Kong","528 Netherlands"])
	

__Using Curl:__

	curl -X DELETE -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-auth-token: <TokenID>' "http://<DNSaaS_API_IP_Address>:8080/geodns" -d '{"record_name": "<record_name>",'domain_name': "<domain_name>", "infoToRemove": [GEO Info to delete]}'

___Returns:___

* __1__ _for success or in case of failure, the description of the error._


## Delete a Geo Map

___Parameters:___

* _Record Name ;_
* _Domain Name ;_
* _TokenID ;_

__Using the DNSaaS Client:__

	DNSaaSClient.deleteGeoMap('<record_name>','<domain_name>',tokenID)


__Using Curl:__

	curl -X DELETE -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-auth-token: <TokenID>' "http://<DNSaaS_API_IP_Address>:8080/geodns" -d '{"record_name": "<record_name>",'domain_name': "<domain_name>"}'
	
___Returns:___

 * __1__ _for success or in case of failure, the description of the error._

