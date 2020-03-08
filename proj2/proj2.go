package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	// You need to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"

	// optional
	_ "strconv"

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg
	// see someUsefulThings() below
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
        var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}
// Helper function that will produce n keys given an initial key.
// This is incase we want to genetate more keys than initially planned.
func createNKeys(n int, initKey []byte) [][]byte {
	// initKey should always be 128 bits, which will be split in half.
	initKeyB1 := initKey[0: 64];
	initKeyB2 := initKey[64:];

	//Feed these two blocks into Argon2key, get another two blocks of keys, 128 each.
	HMACBlocks := userlib.Argon2Key(initKeyB1, initKeyB2, 384);
	HMACB1 := HMACBlocks[0:128];
	HMACB2 := HMACBlocks[128:];
	var returnArray [][]byte;

	for i := 0; i < n; i++ {
		keyBlock, _ := userlib.HMACEval(HMACB1, HMACB2);
		nextKey := keyBlock[0: 128];
		HMACB1 = keyBlock[128: 257];
		HMACB2 = keyBlock[257:];
		returnArray[i] = nextKey;
	}

	return returnArray;
}

func keyFromUserEntry(username string, password string) []byte {
	usernameBytes := []byte(username);
	passwordBytes := []byte(password)
	key := userlib.Argon2Key(usernameBytes, passwordBytes, 128);
	return key;

}
// Given a user-specific safely generated key, and a file name, returns a key to encrypt the data
// and a hash for the file name.

// The structure definition for a user record

// TODO: encrypt with As public key, hand this to B, B can then decpryt wiht this encprted kehy
type User struct {
	Username string;
	Password string;
	FileKey []byte;
	PrivKey userlib.PKEDecKey;
	DSprivateSig userlib.DSSignKey;
	nameKeypairs []fileNameKeyPairs;
	nameUUIDPairs []fileNameUUIDPairs;

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type fileNameKeyPairs struct {
	fileName string;
	fileKey []byte;

}

type fileNameUUIDPairs struct {
	fileName string;
	fileUUID []byte;
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
	initKey := keyFromUserEntry(username, password);

	// We will now generate three keys: One for the UUID, one for encryption the DataStore Struct, and one for
	// the key associated with encrypting files.
	var arrayOfKeys = createNKeys(4, initKey);
	UUIDKey := arrayOfKeys[0];
	JSONKey := arrayOfKeys[1];
	fileKey := arrayOfKeys[2];
	HMACKey := arrayOfKeys[3];

	publicKey, privateKey, _ := userlib.PKEKeyGen();
	privSig, pubSig, _ := userlib.DSKeyGen();

	userlib.KeystoreSet(username, publicKey);
	userlib.KeystoreSet(username + "DS", pubSig);

	var userdata User;
	userdata.Username = username;
	userdata.Password = password;
	userdata.FileKey = fileKey;
	userdata.PrivKey = privateKey;
	userdata.DSprivateSig = privSig;

	userUUID, _ := uuid.FromBytes(UUIDKey[:16])
	marshalled, _ := json.Marshal(userdata);
	tag, _ := userlib.HMACEval(HMACKey, marshalled);
	ivForMarhall := userlib.RandomBytes(16);
	encryptedMarshall := userlib.SymEnc(JSONKey, ivForMarhall, marshalled);
	encryptedPlusTag := append(encryptedMarshall, tag...);

	userlib.DatastoreSet(userUUID, encryptedPlusTag);

	userdataptr = &userdata;

	return &userdata, nil;
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.

func GetUser(username string, password string) (userdataptr *User, err error) {

	initKey := keyFromUserEntry(username, password);
	arrayOfKeys := createNKeys(4, initKey);
	UUIDKey := arrayOfKeys[0];
	JSONKey := arrayOfKeys[1];
	HMACKey := arrayOfKeys[3];
	proposedUUID, _ := uuid.FromBytes(UUIDKey[:16]);
	encryptedStore, exists := userlib.DatastoreGet(proposedUUID);
	decryptedStore := userlib.SymDec(JSONKey, encryptedStore);

	lastItem := len(decryptedStore) - 1;
	startOfTag := lastItem - 512;


	decryptedData := decryptedStore[:startOfTag];
	tag := decryptedStore[startOfTag:];

	computedTag, _ := userlib.HMACEval(HMACKey, decryptedData);

	integrity := userlib.HMACEqual(tag, computedTag);

	var userdata User

	json.Unmarshal(decryptedData, &userdata);

	userdataptr = &userdata

	if !exists && !integrity {
		err.Error()
	} else {
		err = nil;
	}

	return userdataptr, err
}

// This stores a file in the datastore.
//
// The name and length of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

	fileNameBytes := []byte(filename);
	masterFileKey := userdata.FileKey;
	fileNameKey := userlib.Argon2Key(masterFileKey, fileNameBytes, 128);

	UUID_FilePair := createNKeys(3, fileNameKey);
	UUIDKey := UUID_FilePair[0];
	HMACKey := UUID_FilePair[1];
	encKey := UUID_FilePair[2];

	tag, _ := userlib.HMACEval(HMACKey, data);

	initUUID, _ := uuid.FromBytes(UUIDKey); //deterministic from GrandKey + fileName
	IV := userlib.RandomBytes(16);
	encryptedFile := userlib.SymEnc(encKey, IV, data);
	encryptedStore := append(encryptedFile, tag...);
	IVnextUUID := userlib.RandomBytes(16);
	encryptedStore = append(encryptedStore, IVnextUUID...);

	IVforUUID := userlib.RandomBytes(16);
	UUIDtoFile, _ := uuid.FromBytes(IVforUUID);

	userlib.DatastoreSet(UUIDtoFile, encryptedStore);
	userlib.DatastoreSet(initUUID, IVforUUID);

	userlib.DatastoreSet(initUUID, encryptedFile);

	var fileNameData fileNameKeyPairs;
	fileNameData.fileName = filename;
	fileNameData.fileKey = encKey;

	var fileNameUUID fileNameUUIDPairs;
	fileNameUUID.fileName = filename;
	fileNameUUID.fileUUID = IVforUUID;

	userdata.nameKeypairs = append(userdata.nameKeypairs, fileNameData);
	userdata.nameUUIDPairs = append(userdata.nameUUIDPairs, fileNameUUID);

	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	nextUUID := true;

	var fileEncKey []byte;
	//var UUID_IV []byte;

	for _, pairs := range userdata.nameKeypairs {
		if pairs.fileName == filename {
			fileEncKey = pairs.fileKey;
		}
	}

	//for _, pairs := range userdata.nameUUIDPairs {
	//	if pairs.fileName == filename {
	//		UUID_IV = pairs.fileUUID;
	//	}
	//}

	fileNameBytes := []byte(filename);
	masterFileKey := userdata.FileKey;
	fileNameKey := userlib.Argon2Key(masterFileKey, fileNameBytes, 128);

	arrayOfKeys := createNKeys(4, fileNameKey);
	initUUID,_ := uuid.FromBytes(arrayOfKeys[0]);
	HMACKey := arrayOfKeys[1];

	currUUID := initUUID;
	// While loops that points to UUID right before the beginning of a file.
	for nextUUID {
		nextStore, _ := userlib.DatastoreGet(currUUID);
		curUUID, _ := uuid.FromBytes(nextStore);
		_, nextUUID = userlib.DatastoreGet(currUUID);
	}

	UUIDtoAppend := currUUID;
	lastUUID := true;

	for lastUUID {
		storedData, _ := userlib.DatastoreGet(UUIDtoAppend);
		lastIndex := len(storedData) - 1;
		nextUUIDBytes := storedData[lastIndex - 16: ];
		UUIDtoAppend, _ = uuid.FromBytes(nextUUIDBytes);
		_, lastUUID = userlib.DatastoreGet(UUIDtoAppend);
	}

	tag, _ := userlib.HMACEval(HMACKey, data);
	IVforEnc := userlib.RandomBytes(16);
	encFile := userlib.SymEnc(fileEncKey, IVforEnc, data);
	encData := append(encFile, tag...);
	IVnextUUID := userlib.RandomBytes(16);
	encData = append(encData, IVnextUUID...);

	userlib.DatastoreSet(UUIDtoAppend, encData);

	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	nextUUID := true;

	var fileEncKey []byte;
	//var UUID_IV []byte;

	for _, pairs := range userdata.nameKeypairs {
		if pairs.fileName == filename {
			fileEncKey = pairs.fileKey;
		}
	}
	//for _, pairs := range userdata.nameUUIDPairs {
	//	if pairs.fileName == filename {
	//		UUID_IV = pairs.fileUUID;
	//	}
	//}

	fileNameBytes := []byte(filename);
	masterFileKey := userdata.FileKey;
	fileNameKey := userlib.Argon2Key(masterFileKey, fileNameBytes, 128);

	arrayOfKeys := createNKeys(4, fileNameKey);
	initUUID,_ := uuid.FromBytes(arrayOfKeys[0]);
	HMACKey := arrayOfKeys[1];
	//UUIDtoIV, _ := userlib.DatastoreGet(initUUID); // points to UUID that points to file.
	//UUIDtoFile, _ := uuid.FromBytes(UUIDtoIV);

	var returnFile []byte;
	currUUID := initUUID;
	// While loops that points to UUID right before the beginning of a file.
	for nextUUID {
		nextStore, _ := userlib.DatastoreGet(currUUID);
		curUUID, _ := uuid.FromBytes(nextStore);
		_, nextUUID = userlib.DatastoreGet(currUUID);
	}
	// While loop that retrieves all encrypted data.

	allData := true;
	newUUID := currUUID;
	for allData {
		storedData, _ := userlib.DatastoreGet(newUUID);
		lastIndex := len(storedData) - 1;
		newUUIDBytes := storedData[lastIndex - 128:];
		newUUID, _ = uuid.FromBytes(newUUIDBytes);
		tag := storedData[640: lastIndex];
		encFile := storedData[0: lastIndex - 640];
		decFile := userlib.SymDec(fileEncKey, encFile);
		computedHMAC ,_ := userlib.HMACEval(HMACKey, decFile);
		integrity := userlib.HMACEqual(tag, computedHMAC);
		if !integrity {
			err.Error();
		}
		returnFile = append(returnFile, decFile...);
		_, allData = userlib.DatastoreGet(newUUID);

	}
	return returnFile, nil;
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {
	filenameBytes := []byte(filename);
	recipientBytes:=[]byte(recipient);
	senderUUIDBytes := userlib.Argon2Key(filenameBytes, recipientBytes, 128);
	var magicByte []byte;

	var UUIDtoFile []byte;
	var fileNameKey []byte;

	for _, pairs := range userdata.nameUUIDPairs {
		if pairs.fileName == filename {
			UUIDtoFile = pairs.fileUUID;
		}
	}

	for _, pairs := range userdata.nameKeypairs {
		if pairs.fileName == filename {
			fileNameKey = pairs.fileKey
		}
	}

	magicByte = append(magicByte, senderUUIDBytes...);
	magicByte = append(magicByte, UUIDtoFile...);
	magicByte = append(magicByte, fileNameKey...);
	DSsig, _ := userlib.DSSign(userdata.DSprivateSig, magicByte);
	magicByte = append(magicByte, DSsig...);

	receiversPK, _ := userlib.KeystoreGet(recipient);

	encryptedMagicByte, _ := userlib.PKEEnc(receiversPK, magicByte);

	magic_string = hex.EncodeToString(encryptedMagicByte);

	senderUUID, _ := uuid.FromBytes(senderUUIDBytes);

	userlib.DatastoreSet(senderUUID, UUIDtoFile);

	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	fileNameBytes := []byte(filename);
	masterFileKey := userdata.FileKey;
	fileNameKey := userlib.Argon2Key(masterFileKey, fileNameBytes, 128);

	arrayOfKeys := createNKeys(4, fileNameKey);
	initUUID, _ := uuid.FromBytes(arrayOfKeys[0]);

	magicToBytes, _ := hex.DecodeString(magic_string);
	decMagicString, _ := userlib.PKEDec(userdata.PrivKey, magicToBytes);
	sendersUUIDByte := decMagicString[0: 128];
	//UUIDtoFileByte := decMagicString[128: 256];
	sendersFileKey := decMagicString[256: 384];
	Dssignature := decMagicString[384:];
	bodyOfMsg := decMagicString[0: 384];
	pubDS, _ := userlib.KeystoreGet(sender + "DS");
	userlib.DSVerify(pubDS, bodyOfMsg, Dssignature);

	var newKeyPairs fileNameKeyPairs;

	newKeyPairs.fileName = filename;
	newKeyPairs.fileKey = sendersFileKey;

	userlib.DatastoreSet(initUUID, sendersUUIDByte);

	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	filenameBytes := []byte(filename);
	recipientBytes := []byte(target_username);
	senderUUIDBytes := userlib.Argon2Key(filenameBytes, recipientBytes, 128);
	senderUUID, _ := uuid.FromBytes(senderUUIDBytes);
	userlib.DatastoreSet(senderUUID, nil);

	return
}
