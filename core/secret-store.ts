import { SSM } from 'aws-sdk';

//SSM region if you want access paramter store in diffrent region
//Alexa skill may require this to get around with any regional compliance

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
