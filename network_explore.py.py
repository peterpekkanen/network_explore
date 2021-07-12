#!/usr/bin/python3
# -*- coding: utf-8 -*-

#hjälp funktioner
import sys
import ipaddress
import netsnmp
import textwrap
from datetime import datetime 
import MySQLdb

#Get index number from interface IP address
def ipAddr_ifIndex(ipaddr):
    OID = netsnmp.Varbind('ipAdEntIfIndex.'+ipaddr)
    int_index = netsnmp.snmpget(OID, Version = 2, DestHost = sys.argv[2], Community = sys.argv[1])
    
    return int_index[0].decode('utf8')

#Get mac address. ifPhysAddress stores content inhexadecimal
def mac(ipaddr, int_index):
    int_index = str(ipAddr_ifIndex(ipaddr))
    OID = netsnmp.Varbind('ifPhysAddress.'+int_index)
    add_phy = netsnmp.snmpget(OID, Version = 2, DestHost = sys.argv[2], Community = sys.argv[1])
    phys = add_phy[0].hex()
    if len(phys) != 12:
        add_phys = 'N\A'
    else:
        tmp=textwrap.wrap(phys,2)
        add_phys=':'.join(tmp)
    
    return add_phys


def decodetext(result):
    result = result[0]
    result = result.decode('utf-8', 'strict')
    return result




def unit_db(ip, name, model):
    
    mycursor.execute("""INSERT INTO unit ( ip_address, name, model ) VALUES (%s, %s, %s)""", (ip, name, model))
    conn.commit()

def interface_db(prev_id, ip_int, netmask, name_int, mac_adr):
    
    mycursor.execute("""INSERT INTO interface ( unit_id, ip_address, mask, name, mac_address ) VALUES (%s, %s, %s, %s, %s)""", (prev_id, ip_int, netmask, name_int, mac_adr))
    conn.commit()

def grab_id():
    result = mycursor.lastrowid
    return int(result)

def detect_entry(ip):
    mycursor.execute("""SELECT id FROM unit WHERE ip_address = (%s)""", (ip,))
    result = mycursor.fetchone()
    try:
        result = result[0]

    except:
        print("No Entry Detected of the IP Address")

    else:
        delete_entry(result)
        

def delete_entry(idToDelete):
    print("Entry of IP Address detected")
    idToDelete = str(idToDelete)
    mycursor.execute("""DELETE FROM unit WHERE id = (%s)""", (idToDelete,))
    conn.commit()

if len(sys.argv) == 3:


    try:
        community = sys.argv[1] #Andra argumentet som tas in är community string
        ipadress = ipaddress.IPv4Address(sys.argv[2])  #Tredje argumentet som tas in är IP
    except ValueError:
        print("Error: You have entered an invalid IP address")
        exit(1)
        
    #Koppling till mysql
    conn = MySQLdb.connect("localhost", "root", "#netadm05!", "my_network")
    #cursor
    mycursor = conn.cursor()

    detect_entry(sys.argv[2])
    #currentdate = datetime.now()
    #datestring = currentdate.strftime(" %d-%m-%Y-%H:%M:%S")

    #MODEL mib-2.47.1.1.1.1.13.1
    print("Model: ", end=' ')
    oid = netsnmp.Varbind('mib-2.47.1.1.1.1.13') #Varbind behövs för OID
    result = netsnmp.snmpgetnext(oid, Version = 2, DestHost=str(ipadress), Community=community, Timeout=50000, Retries=0)
    decoded = decodetext(result)
    print(decoded)
    model = decoded #LAB4


    #sysname NAMN
    oid = netsnmp.Varbind('sysName.0') #Varbind behövs för OID
    result = netsnmp.snmpget(oid, Version = 2, DestHost=str(ipadress), Community=community, Timeout=50000, Retries=0)
    print("Name: ", end=' ')
    decoded = decodetext(result)
    print(decoded)
    sysname = decoded #LAB4

    unit_db(sys.argv[2], sysname, model) #Skriver till tabellen unit
    prev_id = grab_id()
    #print(type(prev_id))

    #sysDescr
    oid = netsnmp.Varbind('sysDescr') #Varbind behövs för OID
    result = netsnmp.snmpwalk(oid, Version = 2, DestHost=str(ipadress), Community=community, Timeout=50000, Retries=0)
    print("Description: ", end=' ')
    decode = decodetext(result)
    print(decode)
    sysdescription = decoded

    print("---------------------------------------------------------------------")
    #ifDescr #Varje interface
    oid = netsnmp.Varbind('ifDescr') #Varbind behövs för OID
    result = netsnmp.snmpwalk(oid, Version = 2, DestHost=str(ipadress), Community=community, Timeout=50000, Retries=0)
    newLine = 0 #Används för att räkna tills när man gör en ny rad
    for i in result:
        #Itteration av interfaces
        x = i.decode('utf-8', 'strict')
        print(x, end=' ')
        newLine += 1
        if newLine == 4:
            newLine = 0
            print("")
    print("")
    print("--------------------------------------------------------------------------------")

    #ipAdEntAddr
    oid = netsnmp.Varbind('ipAdEntAddr') #Varbind behövs för OID
    result = netsnmp.snmpwalk(oid, Version = 2, DestHost=str(ipadress), Community=community, Timeout=50000, Retries=0) #Hämtas som tulip
    result_list = list(result) #Görs om till lista
 
    titleIP = "IP-Address"
    titleNETMASK = "Netmask"
    titleINTERFACE = "Interface"
    titleMAC = "Mac-Address"
    print("%-20s %-20s %-20s %-15s" %(titleIP,titleNETMASK,titleINTERFACE,titleMAC))



    print("--------------------------------------------------------------------------------")

    for i in result_list:
        i = i.decode('utf-8', 'strict') #i = ip adressen
        oid = netsnmp.Varbind('ipAdEntNetMask.' + str(i)) #Varbind behövs för OID

        result = netsnmp.snmpget(oid, Version = 2, DestHost=str(ipadress), Community=community, Timeout=50000, Retries=0)
        subnetMask = result[0].decode('utf-8', 'strict') #Subnetmask

        ipIndex = ipAddr_ifIndex(i)

        macIndex = mac(i,ipIndex) #MAC Adress
        oid = netsnmp.Varbind('ifDescr.' + str(ipIndex)) #Varbind behövs för OID
        result = netsnmp.snmpget(oid, Version = 2, DestHost=str(ipadress), Community=community, Timeout=50000, Retries=0)
        interface = result[0].decode('utf-8', 'strict') #Via vilket interface

        #Kalla på funktion interface_db
        interface_db(prev_id, i, subnetMask, interface, macIndex)

        print("%-20s %-20s %-20s %-15s" %(i, subnetMask, interface, macIndex))

    
    mycursor.close()
    conn.close()
    print("Closed cursor and connection")
        
else:
    print("Error: You must enter two arguments community and IP-address")
    exit(1)