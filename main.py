from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

import os

def checkPassword(keyName: str, path: str, pssw: str) -> bool:
    try:
        with open(path + '/private_' + keyName + '.pem', 'rb') as file:
            serialization.load_pem_private_key(file.read(), password = pssw.encode());

        return True;
    except:
        return False;

def genKeyPair(keyName: str, keyAlgorithm: str, keySize: int, password: str, path: str):
    try:
        if not password or not isinstance(password, str):
            raise ValueError("Password is empty.");

        if keySize < 2048:
            raise ValueError("Key size must be bigger than 2048");

        if not os.path.isdir(path):
            raise ValueError("Path not found.");

        #Create RSA key pair
        privateKey = rsa.generate_private_key(public_exponent = 65537, key_size = 2048, backend = default_backend());

        #Use private key to PEM format
        privateKeyPem = privateKey.private_bytes(
            encoding = serialization.Encoding.PEM, 
            format = serialization.PrivateFormat.PKCS8,
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
        );

        #Get public key
        publicKey = privateKey.public_key();

        #Use public key PEM format
        publicKeyPem = publicKey.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        );

        #Save key files
        with open(path + '/private_' + keyName + '.pem', 'wb') as f:
            f.write(privateKeyPem);

        with open(path + '/public_' + keyName + '.pem', 'wb') as f:
            f.write(publicKeyPem);

        print("RSA keys have been generated successfully!");
    except Exception as e:
        print("Error", e);

def keyLoad(path: str, keyName: str, password: str):
    try:
        if not os.path.isdir(path):
            raise ValueError("Path not found.");

        if not os.path.isfile(path + '/private_' + keyName + '.pem'):
            raise ValueError("Unable to find file");

        with open(path + '/private_' + keyName + '.pem', 'rb') as file:
            privateKey = serialization.load_pem_private_key(file.read(), password = password.encode());

        print("File loaded successfully!");
    except Exception as e:
        print("Error", e);

def changeName(fileName: str, path: str, newName: str, pssw: str):
    try:
        if not os.path.isdir(path):
            raise ValueError("Path not found.");
        
        if not os.path.isfile(path + '/private_' + fileName + '.pem'):
            raise ValueError("Unable to find private key");

        if not os.path.isfile(path + '/public_' + fileName + '.pem'):
            raise ValueError("Unable to find public key");

        if not checkPassword(keyName = fileName, path = path, pssw = pssw):
            raise ValueError("Password incorrect");

        os.rename(path + '/private_' + fileName + '.pem', path + '/private_' + newName + '.pem');
        os.rename(path + '/public_' + fileName + '.pem', path + '/public_' + newName + '.pem');

        print("File renamed successfully");
    except Exception as e:
        print("Error", e);

def changePassword(fileName: str, path: str, password: str, newPassword: str):
    try:
        if not newPassword:
            raise ValueError("Password must not be empty");
    
        if not os.path.isdir(path):
            raise ValueError("Path not found.");
                
        if not os.path.isfile(path + '/private_' + fileName + '.pem'):
            raise ValueError("Unable to find private key");
                
        if not os.path.isfile(path + '/public_' + fileName + '.pem'):
            raise ValueError("Unable to find public key");
        
        if not checkPassword(keyName = fileName, path = path, pssw = password):
            raise ValueError("Password incorrect");

        with open(path + '/private_' + fileName + '.pem', 'rb') as file:
            privateKey = serialization.load_pem_private_key(file.read(), password = password.encode());

            #Doing so only modifies the password as I use the same privateKey
            privateKeyPem = privateKey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(newPassword.encode())
            );

            with open(path + '/private_' + fileName + '.pem', 'wb') as file:
                file.write(privateKeyPem)

        print("Password changed successfully");
    except Exception as e:
         print("Error", e);

def deleteKey(path: str, keyName: str, password: str):
    try:
        if not os.path.isdir(path):
            raise ValueError("Path not found.");
        
        if not os.path.isfile(path + '/private_' + keyName + '.pem'):
            raise ValueError("Unable to find private key");
        
        if not os.path.isfile(path + '/public_' + keyName + '.pem'):
            raise ValueError("Unable to find public key");

        if not checkPassword(keyName = keyName, path = path, pssw = pssw):
            raise ValueError("Password incorrect");

        os.remove(path + '/private_' + keyName + '.pem');
        os.remove(path + '/public_' + keyName + '.pem');
        
        print("Key deleted successfully");
    except Exception as e:
        print("Error", e);

if __name__ == "__main__":
    # kname = input("Write name: ");
    # pssw = input("Write password: ");
    # ksize = int(input("Write size: "));
    # path = input("Where to save: ");

    # genKeyPair(keyName = kname, keyAlgorithm = "RSA", keySize = ksize, password = pssw, path = path);

    # kname = input("Write name: ");
    # path = input("Where to find: ");
    # pssw = input("Write password: ");

    # keyLoad(keyName = kname, password = pssw, path = path);

    # kname = input("Write name: ");
    # nkname = input("Write new name: ");
    # path = input("Where to find: ");

    # changeName(fileName = kname, path = path, newName = nkname);

    kname = input("Write name: ");
    path = input("Where to find: ");
    pssw = input("Write password: ");

    deleteKey(keyName = kname, path = path, password = pssw);