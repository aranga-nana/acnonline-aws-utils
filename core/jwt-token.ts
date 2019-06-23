import * as jsonwebtoken from 'jsonwebtoken';
import * as uuid from 'uuid/v1'
import { SecretStore } from './secret-store';




const jwt = jsonwebtoken;

export class JwtToken{
    private secretStore:SecretStore;
    constructor(private env:string,private app:string,private aud:string,private iss:string,private ssmkey:string = 'jwt-sign-key'){
        this.secretStore = new SecretStore(app,env);
    }
    getToken = async (username: string, roles: string[] = [],scope:string = 'openid,read,write',expiresIn:string= '5h'):Promise<string> =>{
        const jti= uuid();

        const payload = {
            'sub': username,
            'jti':jti,
            'aud': this.aud,
            'scope': scope,
            'auth': roles
        };
        let signkey:string;
        try{
            signkey = await this.secretStore.getValue(this.ssmkey);
            console.log('sign key',signkey);
            return jwt.sign(payload,signkey, { expiresIn: expiresIn});
        }catch(err){
            console.log(err);
            return null;
        }
    }
    verify = async (token:string):Promise<any> => {
        try{           
            const signKey = await this.secretStore.getValue('jwt-sign-key');
            console.log('signkey:validate',signKey);
            console.log('token:validate',token);
            const success = await jwt.verify(token,signKey);
            console.log('success:JwtToken.verify()',success);
            return success;
        }catch(err){
            console.log(err);
            return null;
        }
    }

}