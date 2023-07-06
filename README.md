# MID Server External Credential Resolver for CyberArk Vault

This is the ServiceNow MID Server custom external credential resolver for the CyberArk vault credential storage.

# Pre-requisites:

CyberArk External Credential Resolver requires JDK 1.8 or newer
Eclipse or any equivalent IDE

# Steps to build
* Clone this repository.
* Import the project in Eclipse or any IDE.
* Update MID Server agent path in pom.xml to point to valid MID Server location.
* Update the code in CyberArkCredentialResolver.java to customize anything.
* Use below maven command or IDE (Eclipse or Intellij) maven build option to build the jar.

	> mvn clean package

* cyberark-external-credentials-0.0.1-SNAPSHOT.jar will be generated under target folder.

# Steps to install and use CyberArk vault as external credential resolver

* Make sure that “External Credential Storage” plugin (com.snc.discovery.external_credentials) is installed in your ServiceNow instance.
* Import the cyberark-external-credentials-0.0.1-SNAPSHOT.jar file from target folder in ServiceNow instance.
	- Navigate to MID Server – JAR Files
	- Create a New Record by clicking New
	- Name it “CyberArkCredentialResolver”, version 0.0.1 and attach cyberark-external-credentials-0.0.1-SNAPSHOT.jar from target folder.
	- Click Submit
* Update the config.xml in MID Server with below parameters and restart the MID Server.

   <parameter name="ext.cred.cyberark.safe_folder" value="<safe_folder>"/> 
   <parameter name="ext.cred.cyberark.safe_name" value="<safe_name>"/> 
   <parameter name="ext.cred.cyberark.app_id" value="ServiceNow_MID_Server"/> 
   <parameter name="ext.cred.cyberark.safe_timeout" value="10"/> 
   <parameter name="ext.cred.cyberark.include_basic_auth_domain" value="<true|false>"/> 

* Create Credential in the instance with "External credential store" flag activated.
* Ensure that the "Credential ID" match the Credential name in your CyberArk credential vault (ex: mycredname)


## Vulnerability Reporting
Please notify psirt-oss@servicenow.com regarding any vulnerability reports in addition to following current reporting procedure.
