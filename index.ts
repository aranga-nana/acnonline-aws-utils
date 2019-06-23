import { SSM } from 'aws-sdk';
import * as jsonwebtoken from 'jsonwebtoken';
import uuid from 'uuid-random';

//SSM region if you want access paramter store in diffrent region
//Alexa skill may require this to get around with any regional compliance
const jwt = jsonwebtoken;
const region =  process.env.SSM_REGION || process.env.AWS_REGION;

let options = {
    apiVersion: '2014-11-06'
}; 
if (region){
    options = Object.assign(options,{region:region})
}
console.log('creating ssm with',JSON.stringify(options));
const ssm = new SSM(options);
export class SecretStore{
    constructor(private appName: string,private env: string){}
    getValue = async (name:string):Promise<string> =>{
        const path = '/'+this.env+'/'+this.appName+'/'
        console.log('secret:path',path);
            return ssm.getParametersByPath({Path:path , Recursive: true, WithDecryption: true}).promise().then(data=>{
                console.log('SSM:data',data);
                if (data.Parameters.length > 0){
                    const filter = path+name;
                    const list = data.Parameters.filter(p => p.Name === filter);
                    if (list.length === 1){
                        return list[0].Value;
                    }
                } else {
                    return null;
                }
            });
    }
};



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

};