package com.snc.discovery;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import com.snc.automation_common.integration.creds.IExternalCredential;
import com.snc.core_automation_common.logging.Logger;
import com.snc.core_automation_common.logging.LoggerFactory;

import javapasswordsdk.PSDKPassword;
import javapasswordsdk.PSDKPasswordRequest;
import javapasswordsdk.PasswordQueryFormat;
import javapasswordsdk.PasswordSDK;
import javapasswordsdk.exceptions.PSDKException;

/**
 * Basic implementation of a CredentialResolver that uses the JavaPasswordSDK API to connect to CyberArk vault.
 */
public class CredentialResolver implements IExternalCredential {

	// Required parameters that must be in the config file in order to use CyberArk.
	// Parameters used to access the vault / credentials
	public static final String SAFE_FOLDER_PROPERTY = "ext.cred.cyberark.safe_folder";
	public static final String SAFE_NAME_PROPERTY = "ext.cred.cyberark.safe_name";
	public static final String SAFE_USER_APP_ID_PROPERTY = "ext.cred.cyberark.app_id";
	public static final String SAFE_TIMEOUT_PROPERTY = "ext.cred.cyberark.safe_timeout";
	public static final String CYBERARK_INCLUDE_DOMAIN_PROPERTY = "ext.cred.cyberark.include_basic_auth_domain";

	private static final String DEFAULT_SAFE_APP_ID = "ServiceNow_MID_Server";
	private static final String DEFAULT_SAFE_TIMEOUT = "10";
	private static final String DEF_SAFE_CREDID_SPLIT = ":";

	private static final String EXT_CRED_API_VERSION = "2.0";

	//Load below parameters from MID config parameters.
	private String safeFolder = "";		// The Safe folder to use as specified in the MID config.xml file (must match folder name in CyberArk)
	private String safeName = "";		// The Safe name to use as specified in the MID config.xml file (must match safe name in CyberArk)
	private String safeAppID = ""; 		// The App-ID used when connecting to CyberArk (can be overridden in the config.xml file)
	private String safeTimeout = "";	// The vault (server) response timeout in seconds to use as specified in the MID config.xml file

	private String includeDomain = ""; 

	// Logger object to log messages in agent.log
	private static final Logger fLogger = LoggerFactory.getLogger(CredentialResolver.class);
	
	public CredentialResolver() {
	}

	/**
	 * Return the API version supported by this class.
	 * Note: should be more than 1.1 for external credential resolver.
	 */
	@Override
	public String getVersion() {
		return EXT_CRED_API_VERSION;
	}

	
	/**
	 * Config method with pre-loaded config parameters from config.xml.
	 * @param configMap - contains config parameters with prefix "ext.cred" only.
	 */
	@Override
	public void config(Map<String, String> configMap) {
		//Note: To load config parameters from MID config.xml if not available in configMap.
		//propValue = Config.get().getProperty("<Parameter Name>")
		
		safeAppID = configMap.get(SAFE_USER_APP_ID_PROPERTY);
		if(isNullOrEmpty(safeAppID)) {
			// use default AppId
			safeAppID = DEFAULT_SAFE_APP_ID;
		}
		
		fLogger.info("SafeAppID: " + safeAppID);
		
		safeTimeout = configMap.get(SAFE_TIMEOUT_PROPERTY);
		if(isNullOrEmpty(safeTimeout)) {
			// use default timeout
			safeTimeout = DEFAULT_SAFE_TIMEOUT;
		}
		
		fLogger.info("safeTimeout: " + safeTimeout);

		includeDomain = configMap.get(CYBERARK_INCLUDE_DOMAIN_PROPERTY);
		if(isNullOrEmpty(includeDomain)) {
			// include domain for windows username by default.
			includeDomain = "false";
		}
		
		fLogger.info("includeDomain: " + includeDomain);

		safeFolder = configMap.get(SAFE_FOLDER_PROPERTY);
		
		fLogger.info("safeFolder: " + safeFolder);
		
		if(isNullOrEmpty(safeFolder))
			throw new RuntimeException("[Vault] INFO - CredentialResolver safeFolder not set!");

		
		
		safeName = configMap.get(SAFE_NAME_PROPERTY);
		
		fLogger.info("safeName: " + safeName);
		
		if(isNullOrEmpty(safeName))
			throw new RuntimeException("[Vault] INFO - CredentialResolver safeSafeName not set!");
		
	}

	/**
	 * Resolve a credential.
	 */
	@Override
	public Map<String, String> resolve(Map<String, String> args) {

		String credId = (String) args.get(ARG_ID);
		String credType = (String) args.get(ARG_TYPE);

		String username = "";
		String password = "";
		String private_key = "";

		if(isNullOrEmpty(credId) || isNullOrEmpty(credType))
			throw new RuntimeException("Invalid credential Id or type found.");

		String policyId = "";

		try {
			// get safeName and policyId from credId if exists.
			String[] parts = credId.split(Pattern.quote(DEF_SAFE_CREDID_SPLIT), -1);
			if (parts.length == 1) {
				credId = parts[0];
			} else if (parts.length == 2) {
				// Ignore safe name field of credId if empty
				if (!parts[0].isEmpty()) {
					safeName = parts[0];
				}
				credId = parts[1];
			}  else if (parts.length == 3) {
				// Ignore safe name field of credId if empty
				if (!parts[0].isEmpty()) {
					safeName = parts[0];
				}
				credId = parts[1];
				policyId = parts[2];
			} else {
				throw new RuntimeException( "Invalid Credential ID: Credential Id has split string more than twice");
			}
			
			fLogger.info("credId: " + credId);
			fLogger.info("credType: " + credType);
			fLogger.info("policyId: " + policyId);
			
			// Connect to vault and retrieve credential
			PSDKPassword psdkPassword = getCred(safeAppID, credId, safeName, safeFolder, policyId, safeTimeout);

			// Grab the username / auth key from the returned object
			username = psdkPassword.getUserName();
			password = psdkPassword.getContent();  // password, private key, etc.

			switch(credType) {
			// for below listed credential type , just retrieve user name and password 
			case "windows":
			case "ssh_password": // Type SSH
			case "vmware":
			case "jdbc":
			case "jms": 
			case "basic":
				username = psdkPassword.getUserName();
				password = psdkPassword.getContent();  // password, private key, etc.

				//Optional: for windows/vmware, include domain name
				if (credType.equals("windows") || credType.equals("vmware")) {
					// add domain in username if not already exists
					if (username.indexOf('\\') < 0 && "true".equalsIgnoreCase(includeDomain)) {
						String domainName = "";
						// domain is the string in the address field.
						String address = psdkPassword.getAddress();
						fLogger.debug("Windows domain name property not found, using address : " + address);
						if (!isNullOrEmpty(address)) {
							domainName = address;
						}

						if (!isNullOrEmpty(domainName)) {
							username = domainName + "\\" + username;
						} else {
							// this is required for windows
							username = ".\\" + username;
						}
					}
				}
				break;
				// for below listed credential type , retrieve user name, password, ssh_passphrase, ssh_private_key
			case "ssh_private_key": 
			case "sn_cfg_ansible": 
			case "sn_disco_certmgmt_certificate_ca":
			case "cfg_chef_credentials":
			case "infoblox": 
			case "api_key":
				// Read operation
				username = psdkPassword.getUserName();
				private_key = psdkPassword.getContent();  // password, private key, etc.

				break;
			case "aws": ;
			case "ibm": ; // softlayer_user, softlayer_key, bluemix_key
			case "azure": ; // tenant_id, client_id, auth_method, secret_key
			case "gcp": ; // email , secret_key
			default:
				fLogger.error("[Vault] INFO - CredentialResolver - invalid credential type found.");
				break;
			}
		} catch (Exception e) {
			// Catch block
			fLogger.error("### Unable to find credential from CyberArk server.", e);
		}
		// the resolved credential is returned in a HashMap...
		Map<String, String> result = new HashMap<String, String>();
		result.put(VAL_USER, username);
		if (isNullOrEmpty(private_key)) {
			result.put(VAL_PSWD, password);
		} else {
			result.put(VAL_PKEY, private_key);
		}
		return result;
	}

	public PSDKPassword getCred(String appId, String credId, String safeName, String safeFolder, String policyId, String safeTimeout) throws PSDKException {
		try {
			PSDKPasswordRequest fRequest = new PSDKPasswordRequest();
			// Format the query for CyberArk
			fRequest.setAppID(appId);

			// Set the timeout to the value defined above, or, the default if not valid
			fRequest.setConnectionTimeout(safeTimeout);

			fRequest.setQueryFormat(PasswordQueryFormat.EXACT);

			String query = formatObjQuery(credId, safeName, safeFolder, policyId);
			fRequest.setQuery(query);
			return PasswordSDK.getPassword(fRequest); // Either works or throws an exception
		} catch (PSDKException ex) {
			// Ignore it, the password will be null and the exception will be handled below
			throw new RuntimeException("The specified credential '" + credId + "' does not exist in the specified vault.", ex);
		}

	}


	private String formatObjQuery(String credId, String safeName, String safeFolder, String policyId) {
		return "safe=" + safeName + ";folder=" + safeFolder + ";object=" + credId +
				(isNullOrEmpty(policyId) ? "" : ";policyid=" + policyId);
	}

	private static boolean isNullOrEmpty(String str) {
		if(str != null && !str.trim().isEmpty())
			return false;
		return true;
	}

	//main method to test cyberark on dev machine where cyberark-AIM is installed.
	//provide cyberark vault details and test it.
	// TODO: Remove this before moving to production
	public static void main(String[] args) {
		CredentialResolver credResolver = new CredentialResolver();
		//credResolver.loadProps();
		credResolver.safeFolder = "root";
		credResolver.safeName = "testsafe";

		Map<String, String> map = new HashMap<>();
		map.put(ARG_ID, "test-win-credentials");
		map.put(ARG_TYPE, "windows");

		Map<String, String> result = credResolver.resolve(map );
		fLogger.info(result.toString());
	}
	
}