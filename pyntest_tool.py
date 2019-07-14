#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Pyntest (https://www.github.com/R3nt0n/pyntest)
# R3nt0n (https://www.github.com/R3nt0n)

import os
import json
import argparse
from subprocess import call, PIPE, Popen, STDOUT

import nmap
import telnetlib
import dns.resolver
import dns.reversename

from lib.traceroute.traceroute import Traceroute


###################################################
# DEFINICIÓN DE ARGUMENTOS
###################################################
parser = argparse.ArgumentParser(description='Analiza la configuración de un dominio.')

parser.add_argument('-d', '--domain', action="store", metavar='', type=str,
                    dest='domain', help='nombre del dominio a analizar',
                    required=True)

parser.add_argument('-j', '--json', action="store", metavar='', type=str,
                    dest='outfile', help='volcar la info a un fichero en formato json',
                    default=False)


###################################################
# COMPROBAR QUE UN HOST ESTÁ ACTIVO
###################################################
def isActive(ip):
    """
    Escaneo superficial de un host mediante nmap para comprobar si está activo.
    :param   ip (str):      dirección IP/nombre del host a comprobar
    :return  active (bool): determina si el host está o no activo
    """
    ns_path=('nmap', '/usr/bin/nmap', '/usr/local/bin/nmap', '/sw/bin/nmap', '/opt/local/bin/nmap', '/usr/share/nmap/scripts')
    scanner = nmap.PortScanner(nmap_search_path=ns_path)
    scanResults = scanner.scan(ip, arguments='-sn')

    if ip in scanResults['scan']:
        active = True
    else:
        active = False
    return active


###################################################
# ESCANEO PROFUNDO DE UN HOST
###################################################
def nmapScan(ip):
    """
    Escaneo profundo de un host utilizando nmap. Primero comprueba si el equipo
    está encendido. En caso afirmativo:

        - Escanea los 65535 puertos TCP mediante la técnica SYN.
        - Trata de determinar sistema operativo, servicios presentes en los
          puertos, software que lo implementa y su versión.
        - Lanza el kit de scripts por defecto establecido por nmap.
        - Como los nombres de host ya los habremos obtenido durante la enumeración
          DNS, no va a intentar hacer ninguna resolución inversa.

    :param   ip (str):           dirección IP/nombre del host a comprobar
    :return: scanResults (dict): contiene toda la info obtenida
    """
    ns_path=('nmap', '/usr/bin/nmap', '/usr/local/bin/nmap', '/sw/bin/nmap', '/opt/local/bin/nmap', '/usr/share/nmap/scripts')
    scanner = nmap.PortScanner(nmap_search_path=ns_path)
    scanResults = scanner.scan(ip, arguments='-Pn -p 25,80')  # Para pruebas rápidas
    #scanResults = scanner.scan(ip, arguments='-Pn -n -sC -O --fuzzy -sV --version-intensity 8 -sS -p 1-65535')
    scanResults = scanResults['scan'][ip]
    return scanResults


###################################################
# COMPROBAR SI UN NS TIENE RECURSIVIDAD ACTIVADA
###################################################
def recursive(ip):
    customResolver = dns.resolver.Resolver()
    customResolver.nameservers = [ip]
    try:
        customResolver.query('test.openresolver.com', 'TXT')
        recursive = True
    except:
        recursive = False

    return recursive


###################################################
# COMPROBAR SI DOMINIO TIENE REGISTRO DMARC
###################################################
def has_dmarc(domain):
    try:
        dns.resolver.query('_dmarc.' + domain, 'TXT')
        dmarc = True
    except:
        dmarc = False

    return dmarc


###################################################
# ESTABLECER CONEXIÓN SMTP PARA DEVOLVER EL BANNER
###################################################
def get_smtp_banner(ip, port):
    try:
        tn = telnetlib.Telnet(ip, port)
        tn.write('EHLO prueba\n')
        tn.write('quit\n')
        try:
            tn.write('exit\n')
        except:
            pass
        banner = tn.read_all()
    except:
        banner = u'Connection refused'

    return banner


###################################################
# COMPROBAR SI UN SERVIDOR DE CORREO ES OPEN RELAY
###################################################
def is_openrelay(ip, port):
    try:
        tn = telnetlib.Telnet(ip, port)
        tn.write('HELO prueba\n')
        tn.write('mail from: test@test.com\n')
        tn.write('rcpt to: test@test.com\n')
        tn.write('quit\n')
        try:
            tn.write('exit\n')
        except:
            pass
        result = tn.read_all()
    except:
        return u'Connection refused'

    openRelay = result
    return openRelay


def get_ptr(ip):
    addr = dns.reversename.from_address(ip)
    try: answer = str(dns.resolver.query(addr, 'PTR')[0])
    except: answer = False
    return answer


###################################################
# COMPROBAR NÚMEROS DE SERIE
###################################################
def serialNumbersMatch(domain, nslist):
    """
    Comprueba si los números de serie de todos los servidores NS son el mismo.

    :param domain (str):   el nombre del dominio a analizar.
    :param nslist (list):  una lista con las IPs de todos los servidores de nombres.

    :return match (bool):  True si todos coinciden, False si hay alguno que difiere.
    """
    serialNumbers = []
    for ip in nslist:
        customResolver = dns.resolver.Resolver()
        customResolver.nameservers = [ip]
        ans = ''
        try:
            answer = customResolver.query(domain, 'SOA')
            for a in answer:
                ans = str(a)
            serialNumber = ans.split(' ')[2]
            serialNumbers.append(serialNumber)
        except dns.resolver.NoNameservers:
            return u'SOA - Incorrect format'
        except:
            return False

    sn = serialNumbers[0]
    match = True
    for num in serialNumbers:
        if num != sn:
            match = False
            break

    return match


###################################################
# COMPROBAR SUBREDES DE NS
###################################################
def nsInSameNetwork(nslist):
    """
    Comprueba que todos los servidores de nombres se encuentran en redes distintas.

    :param nslist (list):     una lista con las ips de todos los servidores de nombres.
    :return: sameNet (bool): devuelve True si hay varios NS en la misma subred, False
                             si todos los NS se encuentran en subredes diferentes.
    """
    networks = []
    for ip in nslist:
        net = ip.split('.')
        net = net[0] + '.' + net[1] + '.' + net[2]
        networks.append(net)

    sameNet = False
    if len(networks) != len(set(networks)):
        sameNet = True

    return sameNet


###################################################
# COMPROBAR VALORES DE TIEMPO DEL SOA
###################################################
def checkSOAvalues(domain):
    """
    Comprueba que todos valores temporales del registro SOA se encuentran dentro
    de los rangos establecidos como adecuados en la correspondiente RFC.

    :param domain (str):   el nombre del dominio a analizar.
    :param nslist (list):  una lista con las IPs de todos los servidores de nombres.
    :return: (tuple):      devuelve una tupla con cuatro booleanos: uno por cada
                           valor temporal, indicando si es correcto o no.
    """
    answer = dns.resolver.query(domain, 'SOA')
    raw_answer = ''
    for line in answer:
        raw_answer += str(line)
    values = str(answer[0])
    values = values.split(' ')

    refresh = int(values[3])
    retry = int(values[4])
    expire = int(values[5])
    minimum = int(values[6])

    refreshTest = u'OK'
    retryTest = u'OK'
    expireTest = u'OK'
    minimumTest = u'OK'

    if (refresh < 1200) or (refresh > 43200):
        refreshTest = u'NO'
    if (retry < 120) or (retry > 7200):
        retryTest = u'NO'
    if (expire < 1209600) or (expire > 2419200):
        expireTest = u'NO'
    if minimum > 86400:
        minimumTest = u'NO'

    refreshTest = u'{}:{}'.format(refreshTest, refresh)
    retryTest = u'{}:{}'.format(retryTest, retry)
    expireTest = u'{}:{}'.format(expireTest, expire)
    minimumTest = u'{}:{}'.format(minimumTest, minimum)

    return raw_answer, refreshTest, retryTest, expireTest, minimumTest


###################################################
# TRACEROUTE
###################################################
def traceroute(ip):
    """
    Realiza un traceroute a una IP de entrada y devuelve la info obtenida en un
    diccionario.
    """
    traceroute = Traceroute(ip)
    info = traceroute.traceroute()
    return info


###################################################
# CONSULTA A RIPE DB
###################################################
def ripe_query(ip):
    """
    Realiza una consulta sobre una IP a la base de datos RIPE y devuelve un
    string con el resultado.
    """
    query = Popen('whois ' + ip, stdout=PIPE, stderr=STDOUT, shell=True)
    output = query.stdout.read()
    return output


###################################################
# ENUMERACIÓN DNS
###################################################
def dnsEnum(domain):
    """
    Examina y organiza toda la información referente a un dominio que se puede
    obtener mediante consultas DNS. El resultado lo vuelca en un fichero JSON.
    Por último lee este fichero y convierte el JSON a una lista de diccionarios
    para poder manipular la información en Python.

        - Intenta descubrir nuevos hosts mediante fuerza bruta, transferencias
          de zona, consultas a Google y a Bing.
        - Realiza resolución inversa de los rangos de IPs que encuentre en los
          registros SPF.

    :param domain (str):  nombre del dominio a analizar
    :return: db (dict):   información obtenida
    """
    tempfile = 'tmp.json'
    returnCode = call('./lib/dnsrecon/dnsrecon.py -d ' + domain + ' -t std -s -j ' + tempfile, shell=True)  # Pruebas rápidas
    #returnCode = call('./lib/dnsrecon/dnsrecon.py -d ' + domain + ' -t std,axfr,brt,goo,bing -s -j ' + tempfile, shell=True)

    db = []

    if returnCode == 0:
        with open(tempfile, 'r') as jsonFile:
            db = json.load(jsonFile)
        os.remove(tempfile)

        # Eliminamos el primer elemento (fecha de ejecucion, argumentos, etc)
        db.pop(0)
        # Eliminamos registros innecesarios
        for reg in db:
            if reg[u'type'] == 'info':
                db.pop(db.index(reg))
            if ('name' in reg) and ((reg[u'name']).startswith('localhost')):
                db.pop(db.index(reg))
        # Limpiamos los registros que quedan
        for reg in db:
            reg.pop(u'zone_server', None)
            reg.pop(u'Version', None)
            reg.pop(u'recursive', None)
            if reg[u'type'] == 'TXT':
                reg.pop(u'name', None)
        # Eliminamos registros duplicados
        seen = set()
        sorted_db = []
        for reg in db:
            t = tuple(reg.items())
            if t not in seen:
                seen.add(t)
                sorted_db.append(reg)
        db = sorted_db

    return db


###################################################
# COMPROBACIÓN DE BLACKLISTS
###################################################
def checkBlacklists(domain):
    """
    Comprueba si el dominio está incluído en alguna lista negra.

    :param   domain (str):    el dominio a analizar.
    :return: output (list):   una lista con la info obtenida:
                              [0] => el número de bases de datos consultadas
                              [1] => en cuántas blacklists se encuentra
                              [2] => URLs de las blacklists en las que está incluído
                                     (separadas por comas)
    """
    os.chdir('lib/blcheck')
    returnCode = call('./blcheck.sh ' + domain + ' > out.tmp', shell=True)

    with open('out.tmp', 'rb') as tempfile:
        output = tempfile.read()

    output = output.split(':')
    if len(output[0]) == 0:
        output = u'Failed to resolve'
    elif int(output[1]) > 0:
        output[2] = (output[2])[:-2]

    os.remove('out.tmp')
    os.chdir('../../')

    return output


###################################################
# PRUEBAS CONTRA IPs (NMAP y TRACEROUTE)
###################################################
def ipScan(db):
    """
    Realiza un escaneo mediante el uso de nmap y traceroute a cada una de los
    hosts activos que contiene el diccionario de entrada, y vuelca la info
    obtenida en él antes de devolverlo.

    :param db (dict):     puede contener info recogida previamente o estar vacío

    :return: db (dict):   el diccionario de entrada, después de haberle añadido
                          la información obtenida
    """
    ips = []
    for reg in db:
        try:
            ip = reg[u'address']
            if ip not in ips:
                ips.append(ip)
        except KeyError:
            pass

    for ip in ips:

        if isActive(ip):
            # Si el host está activo, comienzan pruebas
            scanResults = nmapScan(ip)
            traceResults = traceroute(ip)
            ripeResultsRaw = ripe_query(ip)
            ripeResults = ripeResultsRaw.split('\n')

            ubication = ''
            network = ''
            organization = ''

            for line in ripeResults:
                if 'address' in line:
                    ub_info = (line.split('address:')[-1:][0]).strip(' ')
                    if ub_info not in ubication:
                        ubication += ub_info + ' '
                if 'route' in line:
                    network = line.split(' ')[-1:][0]
                if 'org-name' in line:
                    organization = ((' '.join(line.split('org-name')[-1:])).lstrip(':')).lstrip()

            ubication = ubication.rstrip(' ')

            # Almaceno la info obtenida en la BBDD principal
            for reg in db:
                try:
                    if ip == reg[u'address']:
                        # Almaceno la info de puertos y servicios
                        reg[u'ports'] = {}
                        protoList = scanResults.all_protocols()
                        if 'tcp' in protoList:
                            reg[u'ports'][u'tcp'] = scanResults[u'tcp']
                        if 'udp' in protoList:
                            reg[u'ports'][u'udp'] = scanResults[u'udp']

                        # Almaceno la info del sistema operativo
                        if 'osmatch' in scanResults and len(scanResults[u'osmatch']) > 0:
                            reg[u'os'] = {}
                            reg[u'os'][u'name'] = scanResults[u'osmatch'][0][u'name']
                            reg[u'os'][u'family'] = scanResults[u'osmatch'][0][u'osclass'][0][u'osfamily']
                            reg[u'os'][u'gen'] = scanResults[u'osmatch'][0][u'osclass'][0][u'osgen']
                            reg[u'os'][u'type'] = scanResults[u'osmatch'][0][u'osclass'][0][u'type']
                            reg[u'os'][u'cpe'] = scanResults[u'osmatch'][0][u'osclass'][0][u'cpe'][0]

                        # Almaceno la info de traceroute
                        reg[u'traceroute'] = traceResults

                        # Almaceno la info de la consulta RIPE
                        reg[u'ripe'] = {}
                        reg[u'ripe'][u'query_raw'] = ripeResultsRaw
                        reg[u'ripe'][u'ubication'] = ubication
                        reg[u'ripe'][u'network'] = network
                        reg[u'ripe'][u'organization'] = organization

                except KeyError:
                    pass

    return db


###################################################
# PRUEBAS SEGÚN EL TIPO DE HOST
###################################################
def testServers(domain, db):
    """
    Clasifica los registros que contiene el diccionario en cuatro categorías:
    servidores de nombres, servidores de correo, servidores web y otros servidores.
    Para ello utiliza información relativa al tipo de registro (NS, MX...) y a los
    puertos y servicios presentes.

    En función de ésta clasificación, realizará distintas pruebas contra cada uno
    de ellos.

    :param domain (str):  nombre del dominio al que se van a realizar las pruebas
    :param db (dict):     puede contener info recogida previamente o estar vacío

    :return: db (dict):   el diccionario de entrada, después de haberle añadido
                          la información obtenida
    """

    nslist = []  # Lista de IPs de todos los NS
    spf_count = 0

    for reg in db:
        reg[u'tests'] = {}
        match = False  # Esta variable controla si un servidor ha sido clasificado ya

        if reg[u'type'] == 'NS':
            match = True
            nslist.append(reg[u'address'])
            #####################################################
            # Aquí van todas las pruebas para cada servidor NS  #
            #####################################################
            # ...
            # ...

            ip = reg[u'address']

            # Comprobando si la recursividad está activada
            if recursive(ip):
                reg[u'tests'][u'recursive'] = "True"
            else:
                reg[u'tests'][u'recursive'] = "False"

            # Comprobar que la IP es pública
            ip_public = True
            if (ip.startswith('10.')) or (ip.startswith('172.16.')) or (ip.startswith('192.168.')):
                ip_public = False
            reg[u'tests'][u'ip_public'] = str(ip_public)

            # Organizando la info de transferencia de zona
            for regT in db:
                if (u'zone_transfer' in regT) and (regT[u'ns_server'] == ip):
                    if regT[u'zone_transfer'] == u'failed':
                        reg[u'tests'][u'zone_transfer'] = u'False'
                    else:
                        reg[u'tests'][u'zone_transfer'] = u'True'
                    db.pop(db.index(regT))

            continue

        elif reg[u'type'] == 'MX':
            match = True
            #####################################################
            # Aquí van todas las pruebas para cada servidor MX  #
            #####################################################
            ip = reg[u'address']
            hostname = reg[u'exchange']
            ptr = get_ptr(ip)

            reg[u'PTR'] = str(ptr)

            if ptr:
                if domain in ptr: ptr_match = True
                else: ptr_match = False
                reg[u'tests'][u'ptr_match_domain'] = str(ptr_match)


        if (reg[u'type'] not in ('SOA', 'NS')) and (u'ports' in reg) and (u'tcp' in reg[u'ports']):
            if reg[u'type'] == 'MX':
                hostname = reg[u'exchange']
            else:
                hostname = reg[u'name']
            ip = reg[u'address']

            for port in reg[u'ports'][u'tcp']:
                smtpPort = False
                serviceName = reg[u'ports'][u'tcp'][port][u'name']
                serviceState = reg[u'ports'][u'tcp'][port][u'state']

                #####################################################
                # Pruebas SMTP
                #####################################################
                if 'smtp' in serviceName and 'open' in serviceState:
                    smtpPort = port

                if smtpPort:
                    reg[u'tests'][u'{}_smtp'.format(smtpPort)] = {}

                    banner = get_smtp_banner(ip, smtpPort)
                    reg[u'tests'][u'{}_smtp'.format(smtpPort)][u'banner'] = banner

                    # Comprobar si soporta STARTTLS
                    if 'STARTTLS' in banner:
                        reg[u'tests'][u'{}_smtp'.format(smtpPort)][u'starttls'] = u'True'
                    elif 'Connection refused' in banner:
                        reg[u'tests'][u'{}_smtp'.format(smtpPort)][u'starttls'] = u'Unknown'
                    else:
                        reg[u'tests'][u'{}_smtp'.format(smtpPort)][u'starttls'] = u'False'

                    # Comprobar si es open relay
                    result = is_openrelay(ip, smtpPort)
                    reg[u'tests'][u'{}_smtp'.format(smtpPort)][u'openrelay_raw'] = result

                    if 'Relay access denied' in result:
                        reg[u'tests'][u'{}_smtp'.format(smtpPort)][u'openrelay'] = u'False'
                    elif 'Connection refused' in result:
                        reg[u'tests'][u'{}_smtp'.format(smtpPort)][u'openrelay'] = u'Unknown'
                    else:
                        reg[u'tests'][u'{}_smtp'.format(smtpPort)][u'openrelay'] = u'True'

                    # Comprobar si el banner que devuelve el servidor contiene el nombre del host
                    reg[u'tests'][u'{}_smtp'.format(smtpPort)][u'hostname_in_banner'] = str((hostname in banner))

                #####################################################
                # Pruebas HTTP
                #####################################################
                if 'http' in serviceName and 'open' in serviceState:
                    match = True

                    if (u'script' in reg[u'ports'][u'tcp'][port]) and (u'ssl-cert' in reg[u'ports'][u'tcp'][port][u'script']):
                        protocol = 'https://'
                    else:
                        protocol = 'http://'

                    sitename = protocol + hostname + ':' + str(port) + '/'
                    # ...
                    # ...

        if not match and reg[u'type'] not in ['SOA', 'TXT', 'CNAME']:
            ###########################################################
            # Aquí van todas las pruebas para el resto de servidores  #
            ###########################################################
            if u'name' in reg:
                hostname = reg[u'name']
                #print '[+] Otro tipo de servidor: ' + hostname + '\t=> ' + reg[u'address']

        ###########################################################
        # Pruebas SPF
        ###########################################################
        if reg[u'type'] == 'TXT' and 'spf' in reg[u'strings']:
            spf_count += 1
            spf = reg[u'strings']

    ###########################################################
    # Aquí van todas las pruebas GENERALES POSTERIORES        #
    ###########################################################
    for reg in db:
        if reg[u'type'] == 'SOA':

            # Almacenar si existen servidores NS
            ns_count = len(nslist)
            if ns_count > 0: ns_exists = u'True'
            else: ns_exists = u'False'
            reg[u'tests'][u'ns_exists'] = ns_exists

            # Almacenar cantidad de NS
            if ns_count > 2: ns_count_check = u'OK'
            else: ns_count_check = u'NO'
            reg[u'tests'][u'ns_number'] = u'{}:{}'.format(ns_count_check, ns_count)

            # Comprobar si los NS están en redes distintas
            reg[u'tests'][u'ns_dif_nets'] = str(nsInSameNetwork(nslist))

            # Comprobar concordancia de números de serie
            if serialNumbersMatch(domain, nslist):
                reg[u'tests'][u'serialMatch'] = u'True'
            else:
                reg[u'tests'][u'serialMatch'] = u'False'

            # Comprobar que los valores SOA están dentro de los rangos aceptados
            raw_answer, refreshTest, retryTest, expireTest, minimumTest = checkSOAvalues(domain)
            reg[u'soa_raw'] = str(raw_answer)
            reg[u'tests'][u'validRanges'] = {}
            reg[u'tests'][u'validRanges'][u'refresh'] = str(refreshTest)
            reg[u'tests'][u'validRanges'][u'retry'] = str(retryTest)
            reg[u'tests'][u'validRanges'][u'expire'] = str(expireTest)
            reg[u'tests'][u'validRanges'][u'minimum'] = str(minimumTest)

            # Comprobar si el dominio está incluido en alguna lista negra
            blacklists = checkBlacklists(domain)
            reg[u'tests'][u'blacklist'] = blacklists

            # Comprobar si el dominio tiene registro DMARC
            if has_dmarc(domain):
                reg[u'tests'][u'dmarc_exists'] = u'True'
            else:
                reg[u'tests'][u'dmarc_exists'] = u'False'

            # Comprobar si el dominio tiene registro SPF
            has_spf = bool(spf_count)
            if has_spf:
                reg[u'tests'][u'spf_exists'] = u'True'
            else:
                reg[u'tests'][u'spf_exists'] = u'False'
            reg[u'tests'][u'spf_count'] = spf_count

    return db


###################################################
# FUNCIÓN PRINCIPAL
###################################################
def main():
    #start_time = time.time()

    args = parser.parse_args()
    domain = args.domain
    outfile = args.outfile

    db = dnsEnum(domain)
    # Comprobar que el diccionario no está vacío
    if len(db) == 0:
        json_db = 'ERROR al resolver ' + domain
    else:
        #print '[*] Comienzan tests sobre IPs'
        db = ipScan(db)
        #print '[*] Comienzan tests sobre nombres de servidor'
        db = testServers(domain, db)

        json_db = json.dumps(db, sort_keys=True, indent=4)

    if outfile:
        with open(outfile, 'wb') as f:
            f.write(json_db)
    else:
        print(json_db)

    #print 'Tiempo: {}'.format(time.time() - start_time)



###################################################
# FLUJO DE EJECUCIÓN
###################################################
if __name__ == '__main__':
    main()
