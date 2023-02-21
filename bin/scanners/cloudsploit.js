
import config from "config";
import { exec } from "child_process";
import fs from "fs";
import FileUtils from "../fileUtils.js";


const cloudSploitRootDir = config.get("cloudsploit.rootDir");
const defectDojoModuleNameMaxLength = config.get("defectdojo.data.moduleNameMaxLength");

export default class CloudSploit {
    #logger;
    #fsu;

    constructor(logger) {
        this.#logger = logger;
        this.#fsu = new FileUtils(logger);
    }

    static validateConfigs(configs) {
        //validate cloudsploit section
        if (!configs?.scans?.cloudsploit) {
            throw new Error("Cloudsploit config error: scans.cloudsploit sub context not found in configs");
        }
        //TODO: validate compliences
        //Validate accounts
        const accounts = configs?.scans?.cloudsploit?.accounts;
        if (!accounts || !accounts.length) {
            throw new Error("Cloudsploit config error: scans.cloudsploit.accounts sub context not found or empty");
        }

        const credentials = configs?.credentials
        if (!credentials || !Object.keys(credentials).length) {
            throw new Error("Cloudsploit config error: credentails configs not foud or empty");
        }
        const temp =
        {
            "environmentId": "azure-cypeer-dev",
            "provider": "aws",
            "credentialID": "aws-env1"
        }

        const providerRegex = /^(aws|aws_remediate|azure|azure_remediate|google|google_remediate|oracle|github)$/;
        const envIdSet = {};
        accounts.forEach(account => {
            //validate environment ID
            const envId = account.environmentId;
            if (!envId) {
                const msg = `Cloudsploit config error: Each account should have unique 'environmentId' attribute. But found account instance without 'environmentId' -> ${JSON.stringify(account)}`;
                throw new Error(msg);
            } else if (envIdSet[envId]) {
                const msg = `Cloudsploit config error: Each account should have unique 'environmentId' attribute. But found value '${envId}' duplicated in multiple account configs.`;
                throw new Error(msg);
            } else {
                envIdSet[envId] = true;
            }

            //validate provider
            const provider = account.provider;
            if (!providerRegex.test(account.provider)) {
                const msg = `Cloudsploit config error: Each account should have valid 'provider' attribute. But found account instance with no/invalid 'provider' -> ${JSON.stringify(account)}`;
                throw new Error(msg);
            }

            //validate credentialId
            const credId = account.credentialID;
            if (!credId) {
                const msg = `Cloudsploit config error: Each account should have valid 'credentialID' attribute. But found account instance without 'credentialID' -> ${JSON.stringify(account)}`;
                throw new Error(msg);
            } else if (!credentials[credId]) {
                const msg = `Cloudsploit config error: Each account should have valid 'credentialID' attribute. But found value '${credId}' which is not a valid 'credentialID' as it is not found in credentials.`;
                throw new Error(msg);
            }

        });
    }


    async executeScan(scanConfigs, reportsDirectory) {
        const envId = scanConfigs.environmentId;
        console.log(`\n$$ cloudsploit scan for: ${envId}`)
        const cloudSploitReportsPath = `${reportsDirectory}/cloudsploits/${envId}`
        const configFilePath = `${cloudSploitReportsPath}/cloud-sploit-config-${envId}.js`;
        const cloudPloitConsoleOutputPath = `${cloudSploitReportsPath}/cloudsploit-console-${envId}.txt`
        const cloudPloitErrorOutputPath = `${cloudSploitReportsPath}/cloudsploit-error-${envId}.txt`
        const cloudPloitOutputPath = `${cloudSploitReportsPath}/cloudsploit-report-${envId}.json`
        const cloudSploitEnhancedOutputPath = `${cloudSploitReportsPath}/cloudsploit-enhanced-report-${envId}.json`

        try {
            this.#fsu.mkDirIfNotExist(cloudSploitReportsPath);
            this.#generageConfigFile(scanConfigs, configFilePath)
            await this.#executeCommand(configFilePath, cloudPloitOutputPath, cloudPloitConsoleOutputPath);
            return await this.#enhanceResult(cloudPloitOutputPath, cloudSploitEnhancedOutputPath);
        } catch (error) {
            throw (error);
        } finally {
            //Delete temp files
            if (fs.existsSync(configFilePath)) {
                fs.unlinkSync(configFilePath)
            }
        }
    }

    #generageConfigFile(scanConfigs, filepath) {
        // scanConfigs
        const scfg = {};
        scfg[scanConfigs.provider] = true; //this key will be <cloudprovider> or <cloudprovider>_remediate
        scfg[scanConfigs.credentials.provider] = scanConfigs.credentials;
        const credentials = {};
        const credTemplate = {
            aws: {
                access_key: scfg.aws?.accessKey,
                secret_access_key: scfg.aws?.secretAccessKey,
                session_token: scfg.aws?.sessionToken,
                plugins_remediate: ['bucketEncryptionInTransit']
            },
            aws_remediate: {
                access_key: scfg.aws?.accessKey,
                secret_access_key: scfg.aws?.secretAccessKey,
                session_token: scfg.aws?.sessionToken,
            },
            azure: {
                application_id: scfg.azure?.applicationID,
                key_value: scfg.azure?.keyValue,
                directory_id: scfg.azure?.directoryID,
                subscription_id: scfg.azure?.subscriptionID
            },
            google: {
                project: scfg.google?.project,
                client_email: scfg.google?.clientEmail,
                private_key: scfg.google?.privateKey
            },
            oracle: {
                tenancy_id: scfg.oracle?.tenancyId,
                compartment_id: scfg.oracle?.compartmentId,
                user_id: scfg.oracle?.userId,
                key_fingerprint: scfg.oracle?.keyFingerprint,
                key_value: scfg.oracle?.keyValue
            },
            github: {
                token: scfg.github?.token,
                url: scfg.github?.url,
                login: scfg.github?.login,
                organization: scfg.github?.organization
            }
    
        }
    
        credentials.azure = scfg.azure ? credTemplate.azure : {};
        credentials.azure_remediate = scfg.azure_remediate ? credTemplate.azure : {};
        credentials.aws = scfg.aws ? credTemplate.aws : {};
        credentials.aws_remediate = scfg.aws_remediate ? credTemplate.aws_remediate : {};
        credentials.google = scfg.google ? credTemplate.google : {};
        credentials.google_remediate = scfg.google_remediate ? credTemplate.google : {};
        credentials.oracle = scfg.oracle ? credTemplate.oracle : {};
        credentials.github = scfg.github ? credTemplate.github : {};
    
    
        const fileOut = `module.exports = { \
            credentials: ${JSON.stringify(credentials, null, 2)}\
        }`;
    
        // console.log(fileOut)
        fs.writeFileSync(filepath, fileOut);
    
    }

    //async function using promise
    #executeCommand(configPath, jsonOutputPath, cloudPloitConsoleOutputPath) {
        return new Promise((resolve, reject) => {
            const configs = { cwd: `${cloudSploitRootDir}` }
            const callback = (error, stdout, stderr) => {
                if (error) {
                    reject(error)
                } else if (stderr) {
                    reject(new Error(stderr))
                } else {
                    resolve(stdout)
                }
            }
            const cldspltCommand = `node . --config ${configPath} --console=none --json ${jsonOutputPath}`;
            console.debug(`cloudsploit command: ${cldspltCommand}`)
            const cloudsploitscanExec = exec(cldspltCommand, configs, callback);

            // cloudsploitscanExec.stdout.pipe(process.stdout)

            cloudsploitscanExec.stdout.on('data', (data) => {
                fs.appendFileSync(cloudPloitConsoleOutputPath, data);
                data = data.trim().replaceAll('\n', '\ncloud-sploit : ')
                console.info(`cloud-sploit : ${data}`);
            });

            cloudsploitscanExec.stderr.on('data', (data) => {
                fs.appendFileSync(cloudPloitConsoleOutputPath, data);
                console.error(`cloudsploitscanExec stderr: ${data}`);
            });

            cloudsploitscanExec.on('close', (code) => {
                if (code !== 0) {
                    console.error(`cloudsploitscanExec process exited with code ${code}`);
                }
            });
        });


    }

    // enhanceCloudSploitResult
    async #enhanceResult(inputJsonFilePath, outputJsonFilePath) {
        let inputJson = this.#fsu.getJsonFromFile(inputJsonFilePath);
        let found = 0;
        console.log("Enhansing cloud sploit results");
        let enhancedResult = inputJson.map(element => {
            if (element.resource?.length > defectDojoModuleNameMaxLength) {
                found++;
                const res = element.resource;
                element.description = `${element.description}. \n fullResourcePath: ${res}`
                element.resource = "...".concat(res.substring(res.length - (defectDojoModuleNameMaxLength - 3)))
            }
            return element;
        })

        console.log(`${found} entries enhanced`);
        if (found > 0) {
            console.log(`Writing enhanced output to: ${outputJsonFilePath}`);
            this.#fsu.writeJsonToFile(outputJsonFilePath, enhancedResult);
            // const enhancedResultStr = JSON.stringify(enhancedResult, null, 2);
            // fs.writeFileSync(outputJson, enhancedResultStr);
            // console.log(`File write completed.`);
            return outputJsonFilePath;
        } else {
            return inputJsonFilePath;
        }

    }
}