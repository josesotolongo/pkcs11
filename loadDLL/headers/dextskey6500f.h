/*
 * dextskey6500f.h 
 * Header file for SafeNet skey6500 D-extension functions. 
 *
 * Copyright © 2012 SafeNet, Inc. All rights reserved.
 */

/*
 * Data structures are defined here.
 */
#ifdef CK_NEED_DEFINE_STRUCTS

#define MSG_PKT_MAX_MSG			 2048 // Largest Message Size
#define MAX_CERT_LENGTH    MSG_PKT_MAX_MSG
#define MAX_CRL_LENGTH     MSG_PKT_MAX_MSG

# pragma pack (1)
typedef struct _skeyInitTokenParams
{
  /* Other */
  CK_ULONG    RTCEpochTime;           // RTC time on the token
  CK_BYTE     adminMaxRetries;        // Max retries by an admin

  /* PQ */
  CK_BYTE     pqMinPinLen;            // Min PIN length required 
  CK_BYTE     pqMaxPinAge;            // Max possible PIN life in weeks
  CK_BYTE     pqMinPinAge;            // Min PIN life in days
  CK_BYTE     pqWarnPeriod;           // Wanring period in days before PIN expired
  CK_BYTE     pqHistorySize;          // Password histroy size
  CK_BYTE     pqMaxRepeated;          // Max consecutive repetitions of the same character in PIN
  CK_BYTE     pqMixChars;             // Min characters required in PIN
  CK_BYTE     pqMixLevel;             // Mix of possible characters in PIN 
  CK_BYTE     pqNumbers;              // Numbers are allowed in PIN
  CK_BYTE     pqUpperCase;            // Upper case letters are allowed in PIN
  CK_BYTE     pqLowerCase;            // Lower case letters are allowed in PIN
  CK_BYTE     pqSpecial;              // Special symbols are allowed in PIN
  CK_BYTE     pqAdminMaxPinAge;       // Max possible PIN life for SO in DAYS
} skeyInitTokenParams;
# pragma pack ()

#endif

/* 
 * Function:     D_IsTokenPresent
 * Description:  This API determines if a skey6500 token is present on the slot
 * Parameter:    slotID - ID of the token's slot
 * Returns:      True if Skey6500 token is on the slot or false if it's not
 */
CK_DEXT_FUNCTION_INFO(BOOL, D_IsTokenPresent)
#ifdef CK_NEED_ARG_LIST
(
  CK_SLOT_ID    slotID 
);
#endif

/* 
 * Function:     D_NumDaysTilPinExpires 
 * Desciption:   This API returns the number of days till the PIN expires for the logged 
 *               in user or SO. 
 * Parameter:    slotID - ID of the token's slot
 * Returns:      Number of days till PIN expires
 */
CK_DEXT_FUNCTION_INFO(CK_LONG, D_NumDaysTilPinExpires)
#ifdef CK_NEED_ARG_LIST
(
  CK_SLOT_ID    slotID 
);
#endif

/* 
 * Function:     D_GetATR 
 * Description:  This API retrieves ATR from token after reset.
 * Parameters:   hSession - session's handle
 *               *atr - pointer to the receives ATR (AnswerToReset) structure
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_GetATR)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession, 
  AnswerToReset     *atr
);
#endif

/* 
 * Function:     D_GetTokenSerialNumber
 * Description:  This API retrieves the serial number of the token on the slot.
 * Parameters:   slotID - ID of the token's slot
 *               pSNBuffer - buffer where the Serial Number is stored
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_GetTokenSerialNumber)
#ifdef CK_NEED_ARG_LIST
(
  CK_SLOT_ID    slotID, 
  CK_BYTE_PTR   pSNBuffer 
);
#endif

/*
 * Function:     D_SetAttributeValue_Device
 * Description:  This API sets an attribute on an object and ensures it has SO + User access rights
 * Parameters:   hSession - the current session
 *               hObject - the handle to the object we are modifying
 *               pTemplate - the value we want to set
 *               uxCount - length of the template
 * Returns:      CKR_OK if successful, applicable error code if not
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_SetAttributeValue_Device)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG uxCount
);
#endif

/* 
 * Function:     D_CertCheckValidity
 * Description:  This API is used to load and verify a X.509 Certificate by checking its 
 *               validity dates and if specified, walking its chain of trust. This function 
 *               will validate that each node in the trust chain is trusted and can be 
 *               cryptographically validated. Depending on the certificate type this API 
 *               will also check the CRL to ensure the certificate has not been revoked.
 * Parameters:   hSession - session's handle
 *               length - size of the certificate and it should not exceed 2048 bytes
 *               cert - certificate blob to be validated
 * Returns:      CKR_OK if successful, or
 *               CKR_DATA_LEN_RANGE if the Cert file size is too big, or
 *               other applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_CertCheckValidity)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession, 
  CK_ULONG          length, 
  CK_BYTE_PTR       cert
);
#endif

/* 
 * Function:     D_ClearExtMemObjects 
 * Description:  This API clears objects from SC6500 series extended memory of the session
 * Parameter:    hSession - the session's handle 
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_ClearExtMemObjects)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession
);
#endif

/* 
 * Function:     D_ClearLog
 * Description:  This API sigals the token to purge all audit log records.
 * Parameters:   hSession - session's handle
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_ClearLog)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession
);
#endif

/* 
 * Function:     D_CloseActivation
 * Description:  This API will send an APDU command to the token that the key split has 
 *               successfully been saved and the token should save the complimentary 
 *               split in its internal memory.
 * Parameters:   hSession - session's handle
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_CloseActivation)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession
);
#endif

/* 
 * Function:     D_CRLValidate
 * Description:  This API is used to load and verify a CRL by walking its chain of trust and 
 *               ensuring that each link in the chain is trusted. 
 * Parameters:   hSession - session's handle
 *               length - size of the CRL data, and it should not exceed 2048 bytes
 *               crl - points to CRL data blob
 * Returns:      CKR_OK if successful, or
 *               CKR_DATA_LEN_RANGE if the CRL file size is too big, or
 *               other applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_CRLValidate)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,
  CK_ULONG          length, 
  CK_BYTE_PTR       crl
);
#endif

/* 
 * Function:     D_DecryptSplit 
 * Description:  This API will send a DecryptSplit APDU to the Activation applet on the token. 
 *               The account ID associated with the split, the encrypted split and the UTC time 
 *               is delivered with this API. This command will return the new key split in the 
 *               same buffer used for the current split and will return the current time that 
 *               is set on the token.  
 *               NOTE: See the D_GenerateSplit command for the format of the returned data.
 * Parameter:    slotID - ID of the token's slot
 *               accountID - account ID associated with the split
 *               acctLen - account ID length
 *               currentSplit - current split as input and returned split
 *               currentSplitLen - current split length and returned split length
 *               ulCurTime - current time to be set on the token 
 *               pulPreviousTime - current time set on the token
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_DecryptSplit)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,
  CK_CHAR_PTR       accountID,
  CK_ULONG          acctLen,
  CK_BYTE_PTR       currentSplit,
  CK_ULONG          currentSplitLen,
  CK_ULONG          ulCurTime, 
  CK_ULONG_PTR      pulPreviousTime
);
#endif             

/* 
 * Function:     D_GenerateSplit
 * Description:  This API causes the creation of a new keysplit. One half of the key is stored 
 *               in the token and the other half is encrypted and passed back to the host for 
 *               external storage
 * Parameters:   hSession - session's handle
 *               accountID - account ID to tag the split
 *               acctLen - length of the account ID
 *               reserved - not currently used
 *               newSplit - the returned split with following format:
 *                          32-bit Key header and 36 bytes encrypted data.
 *                          The 32-bit (4-byte) key header has the following format:
 *                           Byte	Description	    Notes
 *                            1	    Domain Number	Valid Value = 0x01 - 0x04
 *                            1	    Key Slot ID	    Valid Value = 0x00 - 0xFF
 *                            2	    Version Number	Valid Value = 0x0000 - 0xFFFF (Increment 1 for every success logon)
 *               newSplitLen - length of the returned key split
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_GenerateSplit)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,
  CK_CHAR_PTR       accountID,
  CK_ULONG          acctLen,
  CK_BBOOL          reserved, 
  CK_BYTE_PTR       newSplit, 
  CK_ULONG_PTR      newSplitLen
);
#endif

/* 
 * Function:     D_GenKeyPair_Device
 * Description:  This API generates a device public/private key pair. This API is identical 
 *               to the PKCS11 C_GenerateKeyPair call with the only difference being the 
 *               APDU sent to the token has a bit flag set to indicate the key pair being 
 *               generated is the device key and not a user key pair.
 * Parameters:   hSession - session's handle
 *               pMechanism - points to the key generation mechanism
 *               pPublicKeyTemplate - points to the template for the public key
 *               uxPublicKeyAttributeCount - the number of attributes in the public-key template
 *               pPrivateKeyTemplate - points to the template for the private key
 *               uxPrivateKeyAttributeCount - the number of attributes in the private-key template
 *               phPublicKey - points to the location that receives the handle of the public key
 *               phPrivateKey - points to the location that receives the handle of the private key
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_GenKeyPair_Device)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR  pMechanism,
  CK_ATTRIBUTE_PTR  pPublicKeyTemplate,
  unsigned int      uxPublicKeyAttributeCount, 
  CK_ATTRIBUTE_PTR  pPrivateKeyTemplate,
  unsigned int      uxPrivateKeyAttributeCount, 
  CK_OBJECT_HANDLE_PTR phPublicKey, 
  CK_OBJECT_HANDLE_PTR phPrivateKey 
);
#endif
 
/* 
 * Function:     D_GetLogSize
 * Description:  This API returns the log size and % full
 * Parameters:   hSession - session's handle
 *               size - size of audit log records
 *               percent - audit log is % full
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_GetLogSize)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,
  CK_ULONG_PTR      size, 
  CK_ULONG_PTR      percent
);
#endif

/* 
 * Function:     D_GetRTC
 * Description:  This API retrieves the current time from the token
 * Parameters:   hSession - session's handle
 *               pDataBuffer - buffer for storing the device time in epoch
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_GetRTC)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,
  CK_ULONG_PTR      pDataBuffer
);
#endif

/*
 * Function:     D_InitPIN
 * Description:  This API sets user pin by SO
 * Parameters:   hSession - the current session
 *               userPin - user's Pin
 *               userPinLen - length of user's Pin
 *               soPin - SO Pin
 *               soPinLen - length of SO Pin
 * Returns:      CKR_OK if successful, applicable error code if not
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_InitPIN)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,
  CK_CHAR_PTR       userPin, 
  CK_ULONG          userPinLen,
  CK_CHAR_PTR       soPin,
  CK_ULONG          soPinLen
);
#endif

/*
 * Function;     D_InitToken
 * Description:  This API initializes an sKey6500 token.
 * Parameters:   slotID - token's slot - input
 *               pPin - pointer to the SO PIN, does not have to be NULL terminated - input
 *               uxPinLen - 16-bit length of the SO PIN - input
 *               pLabel - pointer to the token's label, must be NULL terminated - input
 *               uxDaysExp - number of days for SO PIN expiration - input
 *               pParams - pointer to initialization parameter data, defaults used if NULL - input
 * Returns:      CKR_OK if successful, applicable error code if not
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_InitToken)
#ifdef CK_NEED_ARG_LIST
( 
  CK_SLOT_ID        slotID,
  CK_CHAR_PTR       pPin,
  unsigned short    uxPinLen,
  CK_CHAR_PTR       pLabel,
  CK_LONG           uxDaysExp,
  skeyInitTokenParams* pParams
);
#endif

/* 
 * Function:     D_ReadLog
 * Description:  This API reads event logs from token.
 *               The format of the response is {token serial number | n# of records| signature}.  
 *               The offset defines which record to start at when reading the log file.  The offset 
 *               is referenced from the last entry of the log file. The maximum number of records 
 *               that can be requested is size of the log file returned in the D_GetLogsize.  
 *               If the pDataBuffer value is NULL this function will calculate the required size for 
 *               the requested records and the appended signature and place that in the value pointed 
 *               to by the pDataBufferLen parameter.
 * Parameters:   hSession - session's handle
 *               records - number of records to read
 *               offset - which record to start reading
 *               pDataBuffer - log buffer
 *               pDataBufferLen - buffer size
 *               keyLabel - label
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_ReadLog)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession, 
  CK_ULONG          records,
  CK_ULONG          offset,
  CK_BYTE_PTR       pDataBuffer,
  CK_ULONG_PTR      pDataBufferLen,
  CK_ATTRIBUTE_PTR  keyLabel
);
#endif

/* 
 * Function:     D_CreateUser
 * Description:  This API will create a USER account on the token.
 * Parameters:   hSession - session's handle
 *               maxRetries - max unsuccessful login retries allow
 *               daysUntilPinExpiration - number of days the PIN is valid before it expires
 *               pin - user PIN
 *               pinLen - user PIN length. The PIN length must be between 8 and 20 characters
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_CreateUser)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession, 
  CK_ULONG          maxRetries,
  CK_ULONG          daysUntilPinExpiration, 
  CK_CHAR_PTR       pin, 
  CK_ULONG          pinLen
);
#endif

/* 
 * Function:     D_Zeroize
 * Description:  This API erases the sensitive key parameters
 * Parameters:   hSession - session's handle
 *               type - type of item to be zeroized, possible values are:
 *               1: Domain KEK Split
 *               2: User Account
 *               3: Tampered Device
 *               accountId - for Domain only
 *               acctLen - for Domain only
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_Zeroize)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession, 
  CK_ULONG          type, 
  CK_BYTE_PTR       accountId, 
  CK_ULONG          acctLen
);
#endif

/* 
 * Function:     D_SetRTC
 * Description:  This API sets time on the token
 * Parameters:   hSession - session's handle
 *               epochtime - seconds since epoch 
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_SetRTC)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession, 
  CK_ULONG          epochTime
);
#endif
 
/* 
 * Function:     D_SignPKCS10Request
 * Description:  This API signs the PKCS10 certification request.
 * Parameters:   hSession - session's handle
 *               hPrivateKey - private key handle
 *               pRequestData - PKCS10 request data
 *               ulRequestDataLen - length of data
 *               pSignedRequest - signed PKCS10 request
 *               pulSignedRequestLen - length of signed PKCS10 request
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_SignPKCS10Request)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession, 
  CK_OBJECT_HANDLE  hPrivateKey,
  CK_BYTE_PTR       pRequestData, 
  CK_ULONG	        ulRequestDataLen,
  CK_BYTE_PTR       pSignedRequest, 
  CK_ULONG_PTR      pulSignedRequestLen
);
#endif

/* 
 * Function:     D_GetAllAttributeValues
 * Description:  This API retrieves all attributes of a given object
 * Parameters:   hSession - session's handle
 *               hObject - object handle
 *               pTemplate - retrieved attributes
 *               ulCount - number of bytes of attributes
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_GetAllAttributeValues)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession, 
  CK_OBJECT_HANDLE  hObject, 
  CK_ATTRIBUTE_PTR  pTemplate, 
  CK_ULONG          ulCount
);
#endif

/* 
 * Function:     D_GetTokenType 
 * Description:  This API returns the token type (i.e. sKey6500) that it gets from the tokens 
 *               ATR and configuration information on the token.  
 * Parameter:    slotID - ID of the token's slot
 *               tokenTypePtr - pointer to the type of token 
 *               configInfoPtr - pointer to the configuration info
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_GetTokenType)
#ifdef CK_NEED_ARG_LIST
(
  CK_SLOT_ID    slotID,         /* ID of the token's slot */
  CK_ULONG_PTR  tokenTypePtr,   /* pointer to the type of token */
  CK_ULONG_PTR  configInfoPtr   /* pointer to the configuration info */
);
#endif

/* 
 * Function:     D_ResetUser 
 * Description:  This API resets user's PIN
 * Parameters:   hSession - session's handle
 *               soPin - SO Pin
 *               soPinLen - length of SO Pin
 *               userPin - user's Pin
 *               userPinLen - length of user's Pin
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_ResetUser)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession, 
  CK_CHAR_PTR       soPIN,
  CK_ULONG          soPINLen,
  CK_CHAR_PTR       userPIN,
  CK_ULONG          userPINLen
);
#endif

/* 
 * Function:     D_UnblockUser 
 * Description:  This API allows SO to unblock the user's PIN and reset the number of retries
 * Parameters:   hSession - session's handle
 *               soPin - SO Pin
 *               soPinLen - length of SO Pin
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_UnblockUser)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession, 
  CK_CHAR_PTR       soPIN,
  CK_ULONG          soPINLen
);
#endif

/* 
 * Function:     D_SplitStatus 
 * Description:  This API returns a list of key split information
 * Parameters:   hSession - session's handle
 *               pSplitData - pointer to the data holding the key-split status table.
 *               The Key split status table contains 10 entries and each with following: 
 *               Field 	         Length 	Meaning 
 *               Account ID 	 9 bytes    String given to token during the GenerateSplit command 
 *               Key Slot ID 	 1 byte	    Key slot number 0x00 – 0x09 
 *               Next Slot Flag	 1 byte	    0x00 – False
 *                                          0x01 – True, this location is next location to be 
 *                                            overwritten when performing a GenerateSplit command
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_SplitStatus)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession, 
  CK_BYTE_PTR       pSplitData
);
#endif

// =====================================================================================
// The following D_extensions are provided to allow the use of the CKM_ECDSA_SHA_384 
// mechanism for performing hash_sign and hash_verify operations using ECDSA and SHA384.  
// Currently the PKCS11 version 2.20 specification does not define this mechanism, 
// therefore the D_extensions were added to allow these operations. Each of these 
// D_Extensions follows the same interface definition as its counterpart in the 
// PKCS11 specification.
// =====================================================================================

/* 
 * Function:     D_SignInit 
 * Description:  This API initializes a signature (private key encryption) operation
 * Parameter:    hSession - the session's handle 
 *               pMechanism - the signature mechanism to use
 *               hKey - handle of signature key 
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_SignInit)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession, 
  CK_MECHANISM_PTR  pMechanism, 
  CK_OBJECT_HANDLE  hKey
);
#endif

/* 
 * Function:     D_Sign 
 * Description:  This API signs (encrypts with private key) data in a single part
 * Parameter:    hSession - the session's handle 
 *               pData - the data to sign 
 *               ulDataLen - count of bytes to sign 
 *               pSignature - gets the signature 
 *               pulSignatureLen - gets signature length 
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_Sign)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession, 
  CK_BYTE_PTR       pData, 
  CK_ULONG          ulDataLen, 
  CK_BYTE_PTR       pSignature, 
  CK_ULONG_PTR      pulSignatureLen
);
#endif

/* 
 * Function:     D_SignUpdate 
 * Description:  This API continues a multiple-part signature (signing) operation
 * Parameter:    hSession - the session's handle 
 *               pPart - the data to sign 
 *               ulPartLen - count of bytes to sign 
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_SignUpdate)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession, 
  CK_BYTE_PTR       pPart, 
  CK_ULONG          ulPartLen
);
#endif

/* 
 * Function:     D_SignFinal 
 * Description:  This API completes a multiple-part signature operation
 * Parameter:    hSession - the session's handle 
 *               pSignature - gets the signature 
 *               pulSignatureLen - gets signature length 
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_SignFinal)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession, 
  CK_BYTE_PTR       pSignature, 
  CK_ULONG_PTR      pulSignatureLen
);
#endif

/* 
 * Function:     D_VerifyInit 
 * Description:  This API initializes a verification operation
 * Parameter:    hSession - the session's handle 
 *               pMechanism - the signature mechanism to use
 *               hKey - handle of signature key 
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_VerifyInit)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession, 
  CK_MECHANISM_PTR  pMechanism, 
  CK_OBJECT_HANDLE  hKey
);
#endif

/* 
 * Function:     D_Verify 
 * Description:  This API verifies a signature in a single-part operation
 * Parameter:    hSession - the session's handle 
 *               pData - signed data 
 *               ulDataLen - count of bytes to sign 
 *               pSignature - the signature 
 *               ulSignatureLen - signature length 
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_Verify)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession, 
  CK_BYTE_PTR       pData, 
  CK_ULONG          ulDataLen, 
  CK_BYTE_PTR       pSignature, 
  CK_ULONG          ulSignatureLen
);
#endif

/* 
 * Function:     D_VerifyUpdate 
 * Description:  This API continues a multiple-part verification operation
 * Parameter:    hSession - the session's handle 
 *               pPart - signed data 
 *               ulPartLen - length of signed data 
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_VerifyUpdate)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession, 
  CK_BYTE_PTR       pPart, 
  CK_ULONG          ulPartLen
);
#endif

/* 
 * Function:     D_VerifyFinal 
 * Description:  This API finishes a multiple-part verification
 * Parameter:    hSession - the session's handle 
 *               pSignature - signature to verify  
 *               ulSignatureLen - length of the signature 
 * Returns:      CKR_OK if successful or applicable error code
 */
CK_DEXT_FUNCTION_INFO(CK_RV, D_VerifyFinal)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession, 
  CK_BYTE_PTR       pSignature, 
  CK_ULONG          ulSignatureLen
);
#endif

/*
Function;     D_RepairToken
Description:  Repairs an sKey6500 token or SC650 PKI card that has been incompletely initialized by 
              some other middleware.  The repairs include:
                1) creating a login-retry file if it does not exist, and
                2) creating a PIN-history file if it does not exist.
Parameters:   slotID - token's slot - input
Returns:      status, 0 is success
*/
CK_DEXT_FUNCTION_INFO(CK_RV, D_RepairToken)
#ifdef CK_NEED_ARG_LIST
( 
  CK_SLOT_ID        slotID
);
#endif


/*
Function;     D_ResetUserMaxRetries
Description:  Set the token's max retries and initialize the top value in the count down.
Parameters:   maxRetries - maximum number retries for the user to attempt authentication - input
Returns:      status, 0 is success
*/
CK_DEXT_FUNCTION_INFO(CK_RV, D_ResetUserMaxRetries)
#ifdef CK_NEED_ARG_LIST
( 
  CK_SESSION_HANDLE hSession,
  CK_ULONG          maxRetries
);
#endif

/*
Function;     D_ResetHistoryFile
Description:  Set the History File
Parameters:   hSession - the session's handle 
Returns:      status, 0 is success
*/
CK_DEXT_FUNCTION_INFO(CK_RV, D_ResetHistoryFile)
#ifdef CK_NEED_ARG_LIST
( 
  CK_SESSION_HANDLE hSession
);
#endif
