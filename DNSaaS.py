# Copyright 2014 Copyright (c) 2013-2015, OneSource, Portugal.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

__author__ = 'Claudio Marques / Bruno Sousa - OneSource'
__copyright__ = "Copyright (c) 2013-2015, Mobile Cloud Networking (MCN) project"
__credits__ = ["Claudio Marques - Bruno Sousa"]
__license__ = "Apache"
__version__ = "1.0"
__maintainer__ = "Claudio Marques - Bruno Sousa"
__email__ = "claudio@onesource.pt, bmsousa@onesource.pt"
__status__ = "Production"


# install Web lib
import MySQLdb
import web
import json
import ConfigParser
import httplib2 as http
import time
import os
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse


class msgErrors:
    '''
    Class responsible for the messages of errors
    '''
    updateNotPermitted = {'code': 400, 'msg': 'Update parameter not permitted.'}
    noRecordType = {'code': 400, 'msg': 'Unrecognized record type'}
    objectJson = {'code': 403, 'msg': 'Error in object Json'}
    structJson = {'code': 400, 'msg': 'Provided object does not match schema. Check your data!'}
    noToken = {'code': 401, 'msg': 'Unauthorized!!'}
    noDomain = {'code': 404, 'msg': 'Domain not found!'}
    noRecord = {'code': 404, 'msg': 'Record not found!'}
    duplicate_Domain = {'code': 409, 'msg': 'Domain already exists!'}
    duplicate_Record = {'code': 409, 'msg': 'Record information already exists!'}
    domain_or_record_missed = {'code': 404, 'msg': 'Domain or record not found! Check the IDs correspondent!'}
    geoDNS_conflict = {'code': 400, 'msg': 'The Geo information for this record already exists!!'}
    no_geoDNS_info = {'code': 404, 'msg': 'The Geo information for this record does not exist!!'}


class SOConfigurator:
    """
    Class responsible for DNSaaS configuration.

    """

    fileName_ = 'conf/DNSaaS.conf'
    fileName = os.path.join(os.path.dirname(__file__), fileName_)

    def readConf(self, group, attrName):
        """
        Method used to read from configuration files

        :param group: Confile group
        :param attrName: value
        """
        fileInitialConf = ConfigParser.SafeConfigParser()
        fileInitialConf.readfp(open(self.fileName))
        return fileInitialConf.get(group, attrName)

    def logs(self, log_time, msg_in, msg_rcv, request_type):

        """
        Method responsible for the API logging in file /var/log/dnsaas/api.log

        :param log_time: Time of the operation
        :param msg_in: Message received from user
        :param msg_rcv: Response from the service
        :param request_type: Type of request
        """
        status = self.readConf("LOGGING", "savelog")
        file_ = self.readConf('LOGGING', 'logfile')

        if status == "yes":
            log_time_ = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(log_time))
            actual_log = log_time_, " REQUEST_TYPE: " + request_type + " |**| MSG_IN: " + msg_in + " |**| RESPONSE: " + msg_rcv
            f = open(file_, 'a')
            f.write(str(actual_log) + "\n")
            f.close()

        else:
            pass


class DNSaaSAPI:
    """
    Class responsible to interact with designate API an user.
    """

    def __init__(self, ipDesignate = '', portDesignate = 0, apiurlDesignate = '', apiurlDNSaaSAPI = '',
                 serviceDNSaaSAAA = None, serviceDNSaaSMonitor = None):
        """
    
        :param ipDesignate: The Designate Ip address
        :param portDesignate: The Designate Port
        :param apiurlDesignate: The designate url
        :param apiurlDNSaaSAPI: The DNSaaSAPI url
        :param serviceDNSaaSAAA: The DNSaaSAAA instance
        :param serviceDNSaaSMonitor: The DNSaaSMonitor instance
        """
        self.__ipDesignate = ipDesignate
        self.__portDesignate = portDesignate
        self.__apiurlDesignate = apiurlDesignate
        self.__apiurlDNSaaSAPI = apiurlDNSaaSAPI
        self.__service_DNSaaSAAA = serviceDNSaaSAAA
        self.__service_DNSaaSMONITOR = serviceDNSaaSMonitor

    def createDomain(self, jsonData, tokenId):

        """
        Method used to create domains
        
        :param jsonData: Json request to designate
        :param tokenId: Token
        """
        status, content = self.doRequestDesignate('POST', '/domains', json.dumps(jsonData), tokenId)

        return status, content

    def createRecord(self, jsonData, tokenId):
        """
        Method used to create records
        
        :param jsonData: Json request to designate
        :param tokenId: Token Id
        """

        status, content = self.doRequestDesignate('POST', '/domains/' + str(jsonData['domain_id']) + '/records',
                                                  json.dumps(jsonData['dataRecord']), tokenId)

        return status, content

    def updateDomain(self, jsonData, tokenId):

        """
        Method used to update the domain information
        
        :param jsonData: Json request to designate
        :param tokenId: Token Id
        """

        status, content = self.doRequestDesignate('PUT', '/domains/' + str(jsonData['domain_id']),
                                                  json.dumps(jsonData['dataDomainUpdate']), tokenId)

        return status, content

    def updateRecord(self, jsonData, tokenId):
        """
        Method used to update the record information
        
        :param jsonData: Json request to designate
        :param tokenId: Token Id
        """

        status, content = self.doRequestDesignate('PUT', '/domains/' + str(jsonData['domain_id']) + '/records/' + str(
            jsonData['record_id']), json.dumps(jsonData['dataRecord']), tokenId)

        return status, content

    def deleteDomain(self, jsonData, tokenId):

        """
        Method used to delete a domain.
        
        :param jsonData: Json request to designate
        :param tokenId: Token Id
        """
        status, content = self.doRequestDesignate('DELETE', '/domains/' + str(jsonData['domain_id']), {}, tokenId)

        return status, content

    def deleteRecord(self, jsonData, tokenId):
        """
        Method used to delete a record.
        
        :param jsonData: Json request to designate
        :param tokenId: Token Id

        """

        status, content = self.doRequestDesignate('DELETE',
                                                  '/domains/' + str(jsonData['domain_id']) + '/records/' + str(
                                                      jsonData['record_id']), {}, tokenId)

        return status, content

    def getDomain(self, jsonData, tokenId):

        """
        Method used to get the information about a domain

        :param jsonData: Json request to designate
        :param tokenId: Token

        :returns The Domain information
        """
        status, domains = self.doRequestDesignate('GET', '/domains', '', tokenId)

        if status == '200':
            for domain in domains['domains']:
                if domain['name'] == jsonData['name']:
                    return status, domain
            return '404', {}
        return status, {}

    def getRecord(self, jsonData, tokenId, getAll = False):

        """
        Method used to get the information about a record

        :param jsonData: Json request to designate
        :param tokenId: Token
        :param getAll: If true returns all records for a domain, if false, return only the required

        :returns Record/s information
        """

        status, records = self.doRequestDesignate('GET', '/domains/' + str(jsonData['domain_id']) + '/records/', '',
                                                  tokenId)
        if getAll is False:
            recordsArray = []

            if status == '200':
                for record in records['records']:
                    if record['name'] == jsonData['dataRecord']['name']:
                        recordsArray.append(record)
                return status, recordsArray
        else:
            return status, records

    def requestToken(self, user, password, tenant):

        """
        Method used to get a valid token

        :param user: Username
        :param password: Password
        :param tenant: Tenant Name

        :returns Valid token
        """
        status, content = self.__service_DNSaaSAAA.requestToken(user, password, tenant)

        return status, content

    def doRequestDesignate(self, method, path, body, tokenId):

        """
        Method to perform requests to the Designate. Requests can include creation, delete and other operations.

        :param method: Method to use
        :param path: Path to look for
        :param body: Body of the message
        :param tokenId: Token

        :returns Information about the operation
        """
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json; charset=UTF-8',
            'x-auth-token': tokenId
        }
        target = urlparse(self.__apiurlDesignate + path)
        h = http.Http()
        try:
            response, content = h.request(target.geturl(), method, body, headers)
        except:

            return -1, "Server API not reachable"
        response_status = response.get("status")
        try:
            content_dict = json.loads(content)
        except:
            content_dict = {}

        return response_status, content_dict

    # ## GeoDNS
    def createGeoFile(self, data, flag = False, **kwars):

        """
        Method used to create a geoDns file information for a specific record

        :param data: Information about the record
        :param flag: Flag that control the creation of a new or append to existent
        :param kwars: Arguments

        :return: Return result, Success or failure
        """

        if 'record_name' in kwars:
            record_name = kwars['record_name']
        else:
            record_name = data['record_name']

        if 'domain_name' in kwars:
            domain_name = kwars['domain_name']
        else:
            domain_name = data['domain_name']

        try:
            filePath = "/etc/powerdns/geo-maps/"
            filename = filePath + record_name + "." + domain_name

            if flag is False:
                geomap = data['geoInfo']
                f = open(filename, "w")
                header = ["$RECORD" + " " + record_name + "." + domain_name + "\n",
                          "$ORIGIN" + " " + domain_name + "\n"]
                f.writelines(header)
                f.close()
                f = open(filename, "a")
            else:

                geomap = data['geoInfo']
                f = open(filename, "w")
            for line in geomap:
                f.writelines(line + "\n")

            f.close()
            os.system("pdns_control rediscover")
            return True

        except:

            return False

    def getGeoFile(self, data):

        """
        Method used to get a geoFile content

        :param data: Information about the record

        :return: The file content
        """
        try:
            path = '/etc/powerdns/geo-maps/'
            geoFile = path + data['record_name'] + '.' + data['domain_name']

            tempList = []
            if os.path.isfile(geoFile):
                f = open(geoFile)
                for line in f:
                    tempList.append(line.splitlines())
                f.close()
                tempList_ = []
                for line in tempList:
                    tempList_.append(line[0])
                return tempList_
            else:
                web.NotFound()
                return False
        except:
            return False

    def appendGeoFile(self, data):

        """
        Method used to append new information to an existing geoMap

        :param data: Information to add to file

        :return: Return result, Success or failure
        """
        try:
            geoInfo = data['geoInfo']
            geoFile = self.getGeoFile(data)

            for line in geoInfo:
                geoFile.append(line)
            jsonData = {'geoInfo': geoFile}

            status = self.createGeoFile(jsonData, True, record_name = data['record_name'],
                                        domain_name = data['domain_name'])
            if status is True:
                return True
            else:
                return False
        except:
            return False

    def deleteGeoInfo(self, data):

        """
        Method used to delete information about a geo Record

        :param data: Information about the record to delete
        :return: Return result, Success or failure
        """
        path = '/etc/powerdns/geo-maps/'
        geoFile = path + data['record_name'] + '.' + data['domain_name']

        if os.path.isfile(geoFile):
            if data['infoToRemove'] is False:
                os.remove(geoFile)
                return True

            else:
                fileContent = self.getGeoFile(data)
                infoToRemove = data['infoToRemove']

                for line in infoToRemove:

                    for line2 in fileContent:
                        if line == line2:
                            fileContent.remove(line2)

                jsonData = {'record_name': data['record_name'], 'domain_name': data['domain_name'],
                            'geoInfo': fileContent}
                result = self.createGeoFile(jsonData, True)

                return result
        else:
            web.NotFound()
            return False

    def verify_syntax(self, domain_name):
        """
        Method used to verify the syntax of the domain

        :param domain_name: the domain name
        :return: The domain name with a . at the end
        """
        domain_name = str(domain_name)
        if not domain_name.endswith(".", len(domain_name) - 1, len(domain_name)):
            domain_name = domain_name + "."

        return domain_name

    def verify_record_syntax(self, record_name, domain_name):
        """
        Method used to verify th syntax of the record

        :param record_name: The record name
        :param domain_name: The domain name
        :return: the full record and domain
        """
        domain_name = str(domain_name)
        record_name = record_name + "." + domain_name
        return record_name


class DNSaaSAAA:
    """
    Class responsible to interact wit AAAA
    """

    def __init__(self, ipAAA = '', portAAA = 0, apiurlAAA = ''):
        """
        Initialize class and variables

        :param ipAAA: Keystone IP address
        :param portAAA: Keystone port
        :param apiurlAAA: API path
        """
        self.__ipAAA = ipAAA
        self.__portAAA = portAAA
        self.__apiurlAAA = apiurlAAA

    def requestToken(self, user, password, tenant):
        """
        Method responsible ask for a token.

        :param user: User name
        :param password: Password
        :param tenant: Tenant name
        :rtype : object
        """
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json; charset=UTF-8'
        }
        target = urlparse(self.__apiurlAAA)

        h = http.Http()
        msgJson = {"auth": {"tenantName": tenant, "passwordCredentials": {"username": user, "password": password}}}
        try:
            response, content = h.request(target.geturl(), 'POST', json.dumps(msgJson), headers)
        except:
            return -1, "Server API not reachable"
        response_status = response.get("status")
        return response_status, content


def verifyJson(jsonData, fieldName):
    '''
    Method used to verify the existence of a key in a json message

    :param jsonData: Json message

    '''
    try:
        returnData = jsonData[fieldName]
        return returnData
    except:
        return None


urls = (
    '/domains', 'service_domains',
    '/records', 'service_records',
    '/credentials', 'credentials',
    '/geodns', 'GeoDns',
    '/availability', 'availability'
)

app = web.application(urls, globals())
configFile = SOConfigurator()
serviceDNSaaSAAA = DNSaaSAAA(configFile.readConf('DNSaaSAAA', 'IP'), configFile.readConf('DNSaaSAAA', 'PORT'),
                             configFile.readConf('DNSaaSAAA', 'apiurlAAA'))

service_DNSaaSAPI = DNSaaSAPI(configFile.readConf('DESIGNATE', 'IP'), configFile.readConf('DESIGNATE', 'PORT'),
                              configFile.readConf('DESIGNATE', 'URL'), '', serviceDNSaaSAAA)


class credentials:
    def GET(self):
        """
        Method used to validate user

        :return: Method execution result
        """
        try:
            jsonData = json.loads(web.data())

        except:
            web.forbidden()
            return json.dumps(msgErrors.objectJson)
        if verifyJson(jsonData, 'user') is not None and verifyJson(jsonData, 'password') is not None:

            status, ContentAAA = service_DNSaaSAPI.requestToken(jsonData['user'], jsonData['password'],
                                                                jsonData['tenant'])
            return json.dumps({'status': status, 'data': ContentAAA})
        else:
            web.badrequest()
            return json.dumps(msgErrors.structJson)


class service_domains:
    def POST(self):
        """
        Method used to create a domain

        :return: Method execution result
        """
        try:
            jsonData = json.loads(web.data())
            domain_name = service_DNSaaSAPI.verify_syntax(jsonData['name'])
            ttl = int(jsonData['ttl'])
            email = jsonData['email']
            jsonData = {'name': domain_name, 'ttl': ttl, 'email': email}
            status, response = service_DNSaaSAPI.createDomain(jsonData, web.ctx.env['HTTP_X_AUTH_TOKEN'])

            if status == '200':
                configFile.logs(time.time(), json.dumps(jsonData),
                                json.dumps({'Response ': 1}),
                                "POST DOMAIN")
                return 1

            elif status == '401':
                web.forbidden()
                configFile.logs(time.time(), json.dumps(jsonData), json.dumps(msgErrors.noToken),
                                "POST DOMAIN")
                return json.dumps({'status': status, 'data': msgErrors.noToken})

            elif status == '409':
                web.forbidden()
                configFile.logs(time.time(), json.dumps(jsonData), json.dumps(msgErrors.duplicate_Domain),
                                "POST DOMAIN")
                return json.dumps({'status': status, 'data': msgErrors.duplicate_Domain})

            else:
                web.forbidden()
                configFile.logs(time.time(), 'POST DOMAIN: ' + web.data(), json.dumps(msgErrors.structJson),
                                "POST DOMAIN")
                return json.dumps({'status': status, 'data': msgErrors.structJson})

        except:
            web.forbidden()
            configFile.logs(time.time(), 'POST DOMAIN: ' + web.data(), json.dumps(msgErrors.objectJson), "POST DOMAIN")
            return json.dumps(msgErrors.objectJson)

    def GET(self):
        """
        Method used to get the domain related information

        :return: Method execution result
        """
        try:
            jsonData = json.loads(web.data())
            domain_name = service_DNSaaSAPI.verify_syntax(jsonData['domain_name'])
            msgJson = {'name': domain_name}
            status, response = service_DNSaaSAPI.getDomain(msgJson, web.ctx.env['HTTP_X_AUTH_TOKEN'])

            if status == '200':
                configFile.logs(time.time(), json.dumps(jsonData),
                                json.dumps({'Response code': status, 'data': response}),
                                "GET DOMAIN")
                return json.dumps({'status': status, 'data': response})

            elif status == '401':
                web.badrequest()
                configFile.logs(time.time(), json.dumps(jsonData), json.dumps(msgErrors.noToken),
                                "GET DOMAIN")
                return json.dumps(msgErrors.noToken)

            elif status == '404':
                web.badrequest()
                configFile.logs(time.time(), json.dumps(jsonData), json.dumps(msgErrors.noDomain),
                                "GET DOMAIN")
                return json.dumps(msgErrors.noDomain)

            else:
                web.badrequest()
                configFile.logs(time.time(), 'GET DOMAIN: ' + web.data(), json.dumps(msgErrors.objectJson),
                                "GET DOMAIN")
                return json.dumps(msgErrors.objectJson)

        except:
            web.forbidden()
            configFile.logs(time.time(), 'GET DOMAIN: ' + web.data(), json.dumps(msgErrors.objectJson), "GET DOMAIN")
            return json.dumps(msgErrors.objectJson)

    def PUT(self):
        """
        Method used to update the domain information

        :return: Method execution result
        """
        try:

            jsonData = json.loads(web.data())
            domain_name = service_DNSaaSAPI.verify_syntax(jsonData['domain_name'])
            msgJson = {'name': domain_name}
            status, response = service_DNSaaSAPI.getDomain(msgJson, web.ctx.env['HTTP_X_AUTH_TOKEN'])

            if status == '200':

                parameter_to_update = jsonData['parameter_to_update']
                if parameter_to_update in ['ttl', 'email', 'description']:
                    data = jsonData['data']
                    if parameter_to_update == 'ttl':
                        data = int(data)
                    domain_id = response['id']

                    msgJson = {'domain_id': domain_id, 'dataDomainUpdate': {'' + parameter_to_update + '': data}}

                    status, response = service_DNSaaSAPI.updateDomain(msgJson, web.ctx.env['HTTP_X_AUTH_TOKEN'])
                    configFile.logs(time.time(), json.dumps(jsonData),
                                    json.dumps({'Response ': 1}),
                                    "PUT DOMAIN")

                    return 1
                else:
                    web.badrequest()
                    configFile.logs(time.time(), json.dumps(jsonData), json.dumps(msgErrors.updateNotPermitted),"PUT DOMAIN")
                    return json.dumps(msgErrors.updateNotPermitted)
            elif status == '401':
                web.badrequest()
                configFile.logs(time.time(), json.dumps(jsonData), json.dumps(msgErrors.noToken),
                                "PUT DOMAIN")
                return json.dumps(msgErrors.noToken)

            elif status == '404':
                web.badrequest()
                configFile.logs(time.time(), json.dumps(jsonData), json.dumps(msgErrors.noDomain),
                                "PUT DOMAIN")
                return json.dumps(msgErrors.noDomain)

            else:
                web.badrequest()
                configFile.logs(time.time(), json.dumps(jsonData), json.dumps(msgErrors.objectJson),
                                "PUT DOMAIN")
                return json.dumps(msgErrors.objectJson)

        except:

            web.forbidden()
            configFile.logs(time.time(), 'PUT DOMAIN: ' + web.data(), json.dumps(msgErrors.objectJson), "PUT DOMAIN")

            return json.dumps(msgErrors.objectJson)

    def DELETE(self):
        """
        Method used to delete a domain

        :return: Method execution result
        """
        try:

            jsonData = json.loads(web.data())
            domain_name = service_DNSaaSAPI.verify_syntax(jsonData['domain_name'])
            msgJson = {'name': domain_name}
            status, response = service_DNSaaSAPI.getDomain(msgJson, web.ctx.env['HTTP_X_AUTH_TOKEN'])

            if status == '200':
                domain_id = response['id']
                msgJson = {'domain_id': domain_id}
                statusDelete, response = service_DNSaaSAPI.deleteDomain(msgJson, web.ctx.env['HTTP_X_AUTH_TOKEN'])
                if statusDelete == -1:
                    configFile.logs(time.time(), 'DELETE DOMAIN: ' + web.data(), json.dumps({'Response ': 1}),
                                    "DELETE DOMAIN")
                    return 1

            elif status == '404':
                configFile.logs(time.time(), json.dumps(jsonData), json.dumps(msgErrors.noDomain),
                                "DELETE DOMAIN")
                return json.dumps({'status': status, 'data': msgErrors.noDomain})

            else:
                web.badrequest()
                configFile.logs(time.time(), json.dumps(jsonData), json.dumps(msgErrors.objectJson),
                                "DELETE DOMAIN")
                return json.dumps(msgErrors.objectJson)

        except:
            web.forbidden()
            configFile.logs(time.time(), 'DELETE DOMAIN: ' + web.data(), json.dumps(msgErrors.objectJson),
                            "DELETE DOMAIN")
            return json.dumps(msgErrors.objectJson)


class service_records:
    def POST(self):

        """
        Method used to create a record


        :return: Method execution result
        """
        try:
            jsonData = json.loads(web.data())
            domain_name = service_DNSaaSAPI.verify_syntax(jsonData['domain_name'])
            msgJson = {'name': domain_name}
            status, response = service_DNSaaSAPI.getDomain(msgJson, web.ctx.env['HTTP_X_AUTH_TOKEN'])

            if status == '200':
                domain_id = response['id']
                record_type = jsonData['record_type']

                if record_type in ['A', 'AAAA', 'TXT', 'MX', 'PTR', 'SRV', 'NS', 'CNAME', 'SPF', 'SSHFP', 'NAPTR']:
                    jsonRecord = ''
                    if record_type == 'MX':
                        data = service_DNSaaSAPI.verify_syntax(jsonData['data'])
                        record_name = service_DNSaaSAPI.verify_syntax(jsonData['domain_name'])
                        priority = jsonData['priority']
                        jsonRecord = {'name': record_name, 'type': record_type, 'data': data, 'priority': priority}

                    elif record_type == 'PTR':
                        data = service_DNSaaSAPI.verify_syntax(jsonData['data'])
                        record = service_DNSaaSAPI.verify_syntax(jsonData['record_name'])
                        jsonRecord = {'name': data, 'type': record_type, 'data': record}

                    elif record_type == 'SRV':
                        data = service_DNSaaSAPI.verify_syntax(jsonData['data'])
                        record_name = service_DNSaaSAPI.verify_record_syntax(jsonData['record_name'], domain_name)
                        priority = jsonData['priority']
                        jsonRecord = {'name': record_name, 'type': record_type, 'data': data, 'priority': priority}

                    elif record_type == 'NS':
                        domain_name = service_DNSaaSAPI.verify_syntax(jsonData['domain_name'])
                        data = service_DNSaaSAPI.verify_record_syntax(jsonData['data'], domain_name)
                        jsonRecord = {'name': domain_name, 'type': record_type, 'data': data}

                    elif record_type == 'CNAME':
                        data = service_DNSaaSAPI.verify_syntax(jsonData['data'])
                        record_name = service_DNSaaSAPI.verify_record_syntax(jsonData['record_name'], domain_name)
                        jsonRecord = {'name': record_name, 'type': record_type, 'data': data}

                    elif record_type == 'SPF':
                        data = jsonData['data']
                        record_name = service_DNSaaSAPI.verify_syntax(jsonData['domain_name'])
                        jsonRecord = {'name': record_name, 'type': record_type, 'data': data}

                    elif record_type == 'SSHFP':
                        data = jsonData['data']
                        domain_name = service_DNSaaSAPI.verify_syntax(jsonData['domain_name'])
                        record_name = service_DNSaaSAPI.verify_record_syntax(jsonData['record_name'], domain_name)
                        jsonRecord = {'name': record_name, 'type': record_type, 'data': data}

                    elif record_type == 'NAPTR':
                        data = jsonData['data']
                        priority = jsonData['priority']
                        domain_name = service_DNSaaSAPI.verify_syntax(jsonData['domain_name'])

                        if len(jsonData['record_name']) > 0:
                            record_name = service_DNSaaSAPI.verify_record_syntax(jsonData['record_name'], domain_name)
                        else:
                            record_name = domain_name

                        jsonRecord = {'name': record_name, 'type': record_type, 'data': data, 'priority': int(priority)}

                    elif record_type in ['A', 'TXT', 'AAAA']:
                        data = jsonData['data']
                        record_name = service_DNSaaSAPI.verify_record_syntax(jsonData['record_name'], domain_name)
                        jsonRecord = {'name': record_name, 'type': record_type, 'data': data}

                    msgJson = {'domain_id': domain_id, 'dataRecord': jsonRecord}
                    status, response = service_DNSaaSAPI.createRecord(msgJson, web.ctx.env['HTTP_X_AUTH_TOKEN'])

                    if status == '200':
                        configFile.logs(time.time(), json.dumps(jsonData),
                                        json.dumps({'Response ': 1}), "POST RECORD")

                        return 1

                    elif status == '400':
                        web.forbidden()
                        configFile.logs(time.time(), 'POST RECORD: ' + web.data(), json.dumps(msgErrors.structJson),
                                        "POST RECORD")
                        return json.dumps(msgErrors.structJson)

                    elif status == '401':
                        web.forbidden()
                        configFile.logs(time.time(), 'POST RECORD: ' + web.data(), json.dumps(msgErrors.noToken),
                                        "POST RECORD")
                        return json.dumps(msgErrors.noToken)

                    elif status == '404':
                        web.forbidden()
                        configFile.logs(time.time(), 'POST RECORD: ' + web.data(), json.dumps(msgErrors.noDomain),
                                        "POST RECORD")
                        return json.dumps(msgErrors.noDomain)

                    elif status == '409':
                        web.forbidden()
                        configFile.logs(time.time(), 'POST RECORD: ' + web.data(),
                                        json.dumps(msgErrors.duplicate_Record),
                                        "POST RECORD")
                        return json.dumps(msgErrors.duplicate_Record)

                    else:
                        web.forbidden()
                        configFile.logs(time.time(), json.dumps(jsonData), json.dumps(msgErrors.objectJson),
                                        "POST RECORD")
                        return json.dumps(msgErrors.objectJson)

                else:
                    web.badrequest()
                    configFile.logs(time.time(), 'POST RECORD: ' + web.data(), json.dumps(msgErrors.noRecordType),
                                    "POST RECORD")

                    return json.dumps(msgErrors.noRecordType)

            else:
                web.badrequest()
                configFile.logs(time.time(), "POST RECORD: " + web.data(), json.dumps(msgErrors.noDomain),
                                "POST RECORD")
                return json.dumps(msgErrors.noDomain)
        except:
            web.forbidden()
            configFile.logs(time.time(), "POST RECORD: " + web.data(), json.dumps(msgErrors.objectJson), "POST RECORD")

            return json.dumps(msgErrors.objectJson)

    def GET(self):

        """
        Method used to get a record

        :return: Method execution result
        """
        try:
            jsonData = json.loads(web.data())
            domain_name = service_DNSaaSAPI.verify_syntax(jsonData['domain_name'])
            msgJson = {'name': domain_name}
            status, response = service_DNSaaSAPI.getDomain(msgJson, web.ctx.env['HTTP_X_AUTH_TOKEN'])
            record_type = jsonData['record_type']
            if status == '200' and len(record_type) > 0:
                if record_type in ['NAPTR','MX','NS'] and len(jsonData['record_name']) == 0:
                    record_name = domain_name
                elif record_type in ['PTR','SPF']:
                    record_name = service_DNSaaSAPI.verify_syntax(jsonData['record_name'])
                else:
                    record_name = jsonData['record_name'] + '.' + domain_name

                domain_id = response['id']

                jsonRecord = {'name': record_name}
                msgJson = {'domain_id': domain_id, 'dataRecord': jsonRecord}
                status, response = service_DNSaaSAPI.getRecord(msgJson, web.ctx.env['HTTP_X_AUTH_TOKEN'])

                if len(response) > 0:
                    configFile.logs(time.time(), json.dumps(jsonData), json.dumps({'Response code': status}),
                                    "GET RECORD")

                    for line in response:
                        if line['type'] == jsonData['record_type']:
                            response = line

                    configFile.logs(time.time(), json.dumps(jsonData),
                                    json.dumps({'Response': 1}), "GET RECORD")

                    return json.dumps(response)


                else:

                    web.forbidden()
                    configFile.logs(time.time(), 'GET RECORD: ' + web.data(), json.dumps(msgErrors.noRecord),
                                    "GET RECORD")

                    return json.dumps(msgErrors.noRecord)

            elif status == '200' and len(record_type) == 0:
                domain_id = response['id']
                msgJson = {'domain_id': domain_id}
                status, response = service_DNSaaSAPI.getRecord(msgJson, web.ctx.env['HTTP_X_AUTH_TOKEN'], True)
                configFile.logs(time.time(), json.dumps(jsonData),
                                json.dumps({'Response': 1}), "GET RECORD")
                return json.dumps(response)

            elif status == '401':
                web.forbidden()
                configFile.logs(time.time(), 'POST RECORD: ' + web.data(), json.dumps(msgErrors.noToken), "GET RECORD")
                return json.dumps(msgErrors.noToken)

            elif status == '404':
                web.forbidden()
                configFile.logs(time.time(), 'POST RECORD: ' + web.data(), json.dumps(msgErrors.noDomain), "GET RECORD")
                return json.dumps(msgErrors.noDomain)

            else:

                configFile.logs(time.time(), 'POST RECORD: ' + web.data(), json.dumps(msgErrors.structJson),
                                "GET RECORD")
                return json.dumps({'status': status, 'data': response})

        except:
            web.forbidden()
            configFile.logs(time.time(), "GET RECORD: " + web.data(), json.dumps(msgErrors.objectJson), "GET RECORD")
            return json.dumps(msgErrors.objectJson)

    def PUT(self):

        """
        Method used to change information about a record

        :return: Method execution result
        """
        try:
            jsonData = json.loads(web.data())
            if jsonData['parameter_to_update'] in ['ttl', 'priority', 'data', 'description']:
                domain_name = service_DNSaaSAPI.verify_syntax(jsonData['domain_name'])
                msgJson = {'name': domain_name}
                status, response = service_DNSaaSAPI.getDomain(msgJson, web.ctx.env['HTTP_X_AUTH_TOKEN'])

                if status == '200':

                    domain_id = response['id']
                    if jsonData['record_type'] in ['NAPTR','MX','NS'] and len(jsonData['record_name']) == 0:
                        record_name = domain_name
                    elif jsonData['record_type'] in ['PTR', 'SPF']:
                        record_name = service_DNSaaSAPI.verify_syntax(jsonData['record_name'])
                    else:
                        record_name = jsonData['record_name'] + '.' + domain_name

                    jsonRecord = {'name': record_name}
                    msgJson = {'domain_id': domain_id, 'dataRecord': jsonRecord}
                    status, response = service_DNSaaSAPI.getRecord(msgJson, web.ctx.env['HTTP_X_AUTH_TOKEN'])

                    if len(response) > 0:
                        parameter_to_update = jsonData['parameter_to_update']
                        data = jsonData['data']                       

                        for line in response:

                            if line['type'] == jsonData['record_type']:
                                record_id = line['id']
                                if parameter_to_update in ['ttl', 'priority']:
                                    data == int(data)
                                elif parameter_to_update == 'data' and jsonData['record_type'] =='NS':
                                    data = service_DNSaaSAPI.verify_syntax(jsonData['data'])
                                else:
                                    data = str(data)
                                jsonRecord = {'' + parameter_to_update + '': data}
                                msgJson = {'domain_id': domain_id, 'record_id': record_id, 'dataRecord': jsonRecord}
                                status, response = service_DNSaaSAPI.updateRecord(msgJson,
                                                                                  web.ctx.env['HTTP_X_AUTH_TOKEN'])
                                configFile.logs(time.time(), json.dumps(jsonData),
                                                json.dumps({'Response': 1}), "PUT RECORD")
                                return 1

                    else:
                        web.forbidden()
                        configFile.logs(time.time(), 'PUT RECORD: ' + web.data(), json.dumps(msgErrors.noRecord),
                                        "PUT RECORD")
                        return json.dumps(msgErrors.noRecord)
                else:
                    web.forbidden()
                    configFile.logs(time.time(), 'PUT RECORD: ' + web.data(), json.dumps(msgErrors.noDomain),
                                    "PUT RECORD")
                    return json.dumps(msgErrors.noDomain)
            else:
                configFile.logs(time.time(), 'PUT RECORD: ' + web.data(), json.dumps(msgErrors.updateNotPermitted),
                                "PUT RECORD")
                return json.dumps(msgErrors.updateNotPermitted)
        except:
            web.forbidden()
            configFile.logs(time.time(), 'PUT RECORD: ' + web.data(), json.dumps(msgErrors.objectJson), "PUT RECORD")
            return json.dumps(msgErrors.objectJson)


    def DELETE(self):
        """
        Method used to delete a record

        :return: Method execution result
        """
        try:
            jsonData = json.loads(web.data())

            domain_name = service_DNSaaSAPI.verify_syntax(jsonData['domain_name'])
            msgJson = {'name': domain_name}
            status, response = service_DNSaaSAPI.getDomain(msgJson, web.ctx.env['HTTP_X_AUTH_TOKEN'])

            if status == '200':
                domain_id = response['id']

                if jsonData['record_type'] in ['NAPTR','MX','NS'] and len(jsonData['record_name']) == 0:
                    record_name = domain_name

                elif jsonData['record_type'] in ['PTR','SPF']:
                        record_name = service_DNSaaSAPI.verify_syntax(jsonData['record_name'])

                else:
                    record_name = jsonData['record_name'] + '.' + domain_name

                jsonRecord = {'name': record_name}
                msgJson = {'domain_id': domain_id, 'dataRecord': jsonRecord}
                status, response = service_DNSaaSAPI.getRecord(msgJson, web.ctx.env['HTTP_X_AUTH_TOKEN'])

                if len(response) > 0:
                    configFile.logs(time.time(), json.dumps(jsonData), json.dumps({'Response code': status}),
                                    "GET RECORD")
                    flag = False
                    for line in response:

                        if line['type'] == jsonData['record_type']:
                            flag = True
                            record_id = line['id']

                            jsonRecord = {'domain_id': domain_id, 'record_id': record_id}

                            status, response = service_DNSaaSAPI.deleteRecord(jsonRecord,
                                                                              web.ctx.env['HTTP_X_AUTH_TOKEN'])
                            if status == -1:
                                configFile.logs(time.time(), json.dumps(jsonData),
                                                json.dumps({'Response': 1}), "DELETE RECORD")
                                return 1
                            else:

                                return json.dumps(response)

                    if flag is False:
                        web.forbidden()
                        configFile.logs(time.time(), 'DELETE RECORD: ' + web.data(), json.dumps(msgErrors.noRecord),
                                        "DELETE RECORD")
                        return json.dumps(msgErrors.noRecord)


                else:
                    web.forbidden()
                    configFile.logs(time.time(), 'DELETE RECORD: ' + web.data(), json.dumps(msgErrors.noRecord),
                                    "DELETE RECORD")
                    return json.dumps(msgErrors.noRecord)
            else:
                web.forbidden()
                configFile.logs(time.time(), 'DELETE RECORD: ' + web.data(), json.dumps(msgErrors.noDomain),
                                "DELETE RECORD")
                return json.dumps(msgErrors.noDomain)

        except:
            web.forbidden()
            configFile.logs(time.time(), 'DELETE RECORD: ' + web.data(), json.dumps(msgErrors.objectJson),
                            "DELETE RECORD")
            return json.dumps(msgErrors.objectJson)


class GeoDns:
    def POST(self):

        """
        Method used to create a geoDNs information

        :return:Method execution result
        """
        try:
            jsonData = json.loads(web.data())
            serviceGEORecord = "geo.dnsaas.com."
            domain_name = service_DNSaaSAPI.verify_syntax(jsonData['domain_name'])
            msgJson = {'name': domain_name}
            status, response = service_DNSaaSAPI.getDomain(msgJson, web.ctx.env['HTTP_X_AUTH_TOKEN'])
            # if domain exists
            if status == '200':

                domain_id = response['id']
                record_name = service_DNSaaSAPI.verify_record_syntax(jsonData['record_name'], domain_name)
                jsonRecord = {'name': record_name, 'type': 'CNAME', 'data': record_name + serviceGEORecord}
                msgJson = {'domain_id': domain_id, 'dataRecord': jsonRecord}
                status, response = service_DNSaaSAPI.createRecord(msgJson, web.ctx.env['HTTP_X_AUTH_TOKEN'])

                if status == '200':
                    record_id = response['id']
                    result = service_DNSaaSAPI.createGeoFile(jsonData)

                    if result is True:
                        configFile.logs(time.time(), json.dumps(jsonData),
                                        json.dumps({'Response ': response}), "POST GEODNS")
                        return 1

                    else:
                        jsonRecord = {'domain_id': domain_id, 'record_id': record_id}

                        status, response = service_DNSaaSAPI.deleteRecord(jsonRecord,
                                                                          web.ctx.env['HTTP_X_AUTH_TOKEN'])

                        configFile.logs(time.time(), "POST GEODNS: " + web.data(), json.dumps(msgErrors.objectJson),
                                        "POST GEODNS")

                        return json.dumps(msgErrors.noDomain)

                elif status == '400':
                    web.badrequest()
                    configFile.logs(time.time(), "POST GEODNS: " + web.data(), json.dumps(msgErrors.geoDNS_conflict),
                                    "POST GEODNS")
                    return json.dumps(msgErrors.geoDNS_conflict)

                else:
                    configFile.logs(time.time(), "POST GEODNS: " + web.data(), json.dumps(msgErrors.objectJson),
                                    "POST GEODNS")
                    return json.dumps(msgErrors.objectJson)

            elif status == '404':
                configFile.logs(time.time(), "POST GEODNS: " + web.data(), json.dumps(msgErrors.noDomain),
                                "POST GEODNS")

                return json.dumps(msgErrors.noDomain)

            elif status == '401':
                configFile.logs(time.time(), "POST GEODNS: " + web.data(), json.dumps(msgErrors.noToken),
                                "POST GEODNS")
                return json.dumps(msgErrors.noToken)

        except:

            configFile.logs(time.time(), "POST GEODNS: " + web.data(), json.dumps(msgErrors.objectJson),
                            "POST GEODNS")

            return json.dumps(msgErrors.objectJson)

    def GET(self):

        """
        Method used to get a geoDNs information

        :return: Method execution result
        """
        try:
            jsonData = json.loads(web.data())
            response = service_DNSaaSAPI.getGeoFile(jsonData)
            if response is not False:
                msgJson = {'geoFileContent': response}
                configFile.logs(time.time(), json.dumps(jsonData),
                                json.dumps({'Response ': 1}), "GET GEODNS")
                return json.dumps(msgJson)

            else:
                web.forbidden()
                configFile.logs(time.time(), "GET GEODNS: " + web.data(), json.dumps(msgErrors.no_geoDNS_info),
                                "GET GEODNS")
                return json.dumps(msgErrors.no_geoDNS_info)

        except:
            configFile.logs(time.time(), "GET GEODNS: " + web.data(), json.dumps(msgErrors.objectJson),
                            "GET GEODNS")
            return json.dumps(msgErrors.objectJson)

    def PUT(self):

        try:
            jsonData = json.loads(web.data())
            response = service_DNSaaSAPI.appendGeoFile(jsonData)

            if response is not False:
                configFile.logs(time.time(), json.dumps(jsonData),
                                json.dumps({'Response code': 1}), "PUT GEODNS")
                return 1
            else:
                web.forbidden()
                configFile.logs(time.time(), "PUT GEODNS: " + web.data(), json.dumps(msgErrors.no_geoDNS_info),
                                "PUT GEODNS")
                return json.dumps(msgErrors.no_geoDNS_info)

        except:
            configFile.logs(time.time(), "PUT GEODNS: " + web.data(), json.dumps(msgErrors.objectJson),
                            "PUT GEODNS")
            return json.dumps(msgErrors.objectJson)


    def DELETE(self):

        """
        Method used to delete a geoDNs information


        :return: Method execution result
        """
        try:
            jsonData = json.loads(web.data())

            if jsonData['infoToRemove'] is False:
                domain_name = service_DNSaaSAPI.verify_syntax(jsonData['domain_name'])
                msgJson = {'name': domain_name}
                status, response = service_DNSaaSAPI.getDomain(msgJson, web.ctx.env['HTTP_X_AUTH_TOKEN'])

                if len(response) > 0:
                    domain_id = response['id']
                    record_name = jsonData['record_name'] + '.' + domain_name
                    jsonRecord = {'name': record_name, 'type': 'CNAME'}
                    msgJson = {'domain_id': domain_id, 'dataRecord': jsonRecord}
                    status, response = service_DNSaaSAPI.getRecord(msgJson, web.ctx.env['HTTP_X_AUTH_TOKEN'])

                    if len(response) > 0:
                        record_id = response[0]['id']
                        msgJson = {'domain_id': domain_id, 'record_id': record_id, 'dataRecord': jsonRecord}
                        status, response = service_DNSaaSAPI.deleteRecord(msgJson, web.ctx.env['HTTP_X_AUTH_TOKEN'])

                        if status == -1:
                            status, response = service_DNSaaSAPI.getRecord(msgJson, web.ctx.env['HTTP_X_AUTH_TOKEN'])

                            if status == '200':
                                response = service_DNSaaSAPI.deleteGeoInfo(jsonData)
                                if response is True:
                                    configFile.logs(time.time(), json.dumps(jsonData),
                                                    json.dumps({'Response ': 1}), "DELETE GEODNS")
                                    return 1
                                else:
                                    web.forbidden()
                                    configFile.logs(time.time(), "DELETE GEODNS: " + web.data(),
                                                    json.dumps(msgErrors.no_geoDNS_info),
                                                    "DELETE GEODNS")
                                    return json.dumps(msgErrors.no_geoDNS_info)
                            else:
                                web.forbidden()
                                configFile.logs(time.time(), "DELETE GEODNS: " + web.data(),
                                                json.dumps(msgErrors.no_geoDNS_info),
                                                "DELETE GEODNS")
                            return json.dumps(msgErrors.no_geoDNS_info)

                    else:
                        web.forbidden()
                        configFile.logs(time.time(), "DELETE GEODNS: " + web.data(), json.dumps(msgErrors.noRecord),
                                        "DELETE GEODNS")
                        return json.dumps(msgErrors.noRecord)
                else:
                    configFile.logs(time.time(), "POST GEODNS: " + web.data(), json.dumps(msgErrors.noDomain),
                                    "POST GEODNS")
                    return json.dumps(msgErrors.noDomain)

            else:
                response = service_DNSaaSAPI.deleteGeoInfo(jsonData)

                if response is True:
                    configFile.logs(time.time(), json.dumps(jsonData),
                                    json.dumps({'Response code': 1}), "DELETE GEODNS")
                    return 1
                else:

                    configFile.logs(time.time(), "DELETE GEODNS: " + web.data(), json.dumps(msgErrors.no_geoDNS_info),
                                    "DELETE GEODNS")
                    return json.dumps(msgErrors.no_geoDNS_info)

        except:
            configFile.logs(time.time(), "DELETE GEODNS: " + web.data(), json.dumps(msgErrors.objectJson),
                            "DELETE GEODNS")
            return json.dumps(msgErrors.objectJson)


class availability:
    def GET(self):

        """
        Method used to create a geoDNs information

        :return:Method execution result
        """
        msgJson = {'name': 'API available'}
        return json.dumps(msgJson)


if __name__ == '__main__':
    app.run()


