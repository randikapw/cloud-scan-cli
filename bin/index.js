#!/usr/bin/env node

const yargs = require("yargs");
const { exec, execSync, spawn } = require("node:child_process");
const fs = require("node:fs");
const { default: axios } = require("axios");
var FormData = require('form-data');
const config = require("config");
let authToken;

const commandIdentifier = "cloudscan";
const args = yargs
    .usage(`${commandIdentifier} [-p product name] [-c configfile path] -- one of configs(-c or -p) is required -c have the priority`)
    .option("p", { alias: "product", describe: "product name", type: "string", demandOption: false })
    .option("c", { alias: "config", describe: "configuration json file path", type: "string", demandOption: false })
    .argv

let productName = args.p;
let scanConfigs;


function getJsonFromFile (path) {
    return JSON.parse(fs.readFileSync(path).toString());
}
// exec("cd ..")
//take these from configs
const profileRootDir = config.get("profiles.profileRootDir");
const profileConfigDirName = config.get("profiles.configDirName");
const profileReportsDirName = config.get("profiles.reportsDirName");


function validateArguments() {
    let confArg = args.c;
    if(confArg) {
        confArg = getJsonFromFile(confArg)
        productName = confArg?.product?.name;
        if (!productName) {
            throw new Error("Invalid configuration file! 'product.name' not found in configs");
        }
    }
    const scanConfigDir = `${profileRootDir}/${productName}/${profileConfigDirName}`
    const scanConfigPath = `${scanConfigDir}/scanconfigs.js`
    if (fs.existsSync(scanConfigPath)) {
        if (confArg) {
            console.info(`Configuration for product '${productName}' is already avaialbe and this will run with existing configs. if you want to update configs please user 'pushconfig' command`);
        }
        scanConfigs = getJsonFromFile(scanConfigPath);
    } else if (confArg){
        scanConfigs = confArg;
        const scnCfgStr = JSON.stringify(scanConfigs, null, 2);
        console.log("New product configuration found. Registering new product to configs")
        mkDirIfNotExist(scanConfigDir)
        fs.writeFileSync(scanConfigPath, scnCfgStr);
    console.log(`File write completed.`);
    } else {
        const msg = `Cannot find internal configs for the product '${productName}'. Please use ${commandIdentifier} -c with valid configuration file.`;
        throw new Error(msg);
    }
    
}

const cloudSploitRootDir = config.get("cloudsploit.rootDir");

const dojoHost = config.get("defectdojo.host");
const dojoUserName = config.get("defectdojo.credentials.username");
const dojoPass = config.get("defectdojo.credentials.password");
const defectDojoModuleNameMaxLength = config.get("defectdojo.data.moduleNameMaxLength");

function validateConfigs() {
    mkDirIfNotExist(profileRootDir, "profileRootDir")
    const cloudsploitpackage = `${cloudSploitRootDir}/package.json`
    if(fs.existsSync(cloudsploitpackage)) {
        const pkg = getJsonFromFile(cloudsploitpackage);
        if (pkg?.name !== "cloudsploit") { 
            console.log(pkg)
            throw new Error("Invalid cloudsplit root directory: invalid package.json. Are you refering to deferent node project?");
        }
    } else {
        throw new Error("Invalid cloudsplit root directory. Cannot find cloudsploit package.json");
    }
}

async function mkDirIfNotExist(dirPath, shortName) {
    if (!fs.existsSync(dirPath)) {
        shortName = shortName ? `'${shortName}' d`: 'D';
        console.warn(`${shortName}irecotory '${dirPath}' is not avaialbe. Hence creating it rightnow`)
        fs.mkdirSync(dirPath, {recursive: true})
    }
}


function executeCloudSploitScan(configPath, jsonOutputPath) {
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
            data = data.trim().replaceAll('\n', '\ncloud-sploit : ')
            console.info(`cloud-sploit : ${data}`);
        });

        cloudsploitscanExec.stderr.on('data', (data) => {
            console.error(`cloudsploitscanExec stderr: ${data}`);
        });

        cloudsploitscanExec.on('close', (code) => {
            if (code !== 0) {
                console.error(`cloudsploitscanExec process exited with code ${code}`);
            }
        });
    });


}

async function enhanceCloudSploitResult(inputJsonFilePath, outputJson) {
    let inputJson = require(inputJsonFilePath);
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
    console.log(`Writing enhanced output to: ${outputJson}`);
    const enhancedResultStr = JSON.stringify(enhancedResult, null, 2);
    fs.writeFileSync(outputJson, enhancedResultStr);
    console.log(`File write completed.`);
}

async function defectDojoAuthenticate() {
    var data = JSON.stringify({
        "username": dojoUserName,
        "password": dojoPass
    });

    var config = {
        method: 'post',
        url: `${dojoHost}/api/v2/api-token-auth/`,
        headers: {
            'accept': 'application/json',
            'Content-Type': 'application/json'
        },
        data: data
    };

    const result = await axios(config);
    authToken = result.data.token;
    return result.data;
}

async function defectdojoImportScan(productName, engagementName, scanFilePath, scanType) {
    if (!scanType) scanType = 'Cloudsploit Scan';
    const fileSize = fs.statSync(scanFilePath).size;
    const readStream = fs.createReadStream(scanFilePath);
    let uploadedSize = 0;
    readStream.on('data', function (buffer) {
        var segmentLength = buffer.length;

        // Increment the uploaded data counter
        uploadedSize += segmentLength;

        // Display the upload percentage
        // console.log("Progress:\t",((uploadedSize/zipSize*100).toFixed(2)+"%"));
        let progress = (uploadedSize / fileSize * 100).toFixed(2);
        process.stdout.write(`\rUploading file: ${progress}%`);
        if (progress >= 100) {
            console.log("\nUpload completed, waiting for response after defining all issues.. this may take few minutes...")
        }
    });
    var data = new FormData();
    data.append('scan_date', '2023-01-18');
    data.append('minimum_severity', 'High'); //Info
    data.append('active', 'true');
    data.append('verified', 'false');
    data.append('scan_type', scanType);
    data.append('file', readStream);
    data.append('product_name', productName);
    data.append('engagement_name', engagementName);
    data.append('close_old_findings', 'false');
    data.append('close_old_findings_product_scope', 'false');
    data.append('deduplication_on_engagement', 'true');
    data.append('push_to_jira', 'false');
    data.append('create_finding_groups_for_all_findings', 'true');

    console.log(`Improt scan resutls for scan type '${scanType}' to the product '${productName}' under engagement '${engagementName}'`)
    var config = {
        method: 'post',
        url: `${dojoHost}/api/v2/import-scan/`,
        headers: {
            'accept': 'application/json',
            'Authorization': `Token ${authToken}`,
            ...data.getHeaders()
        },
        //onUploadProgress: progressEvent => process.stdout.write(`\nImporting ${progressEvent.loaded}`),
        data: data
    };

    axios(config)
        .then(function (response) {
            console.log('Import Scan completed');
            console.log(JSON.stringify(response.data));
        })
        .catch(function (error) {
            console.log(error);
        });
}

async function defectdojoGetProductsByName(productName, exactFirstByExactMatch) {
    var config = {
        method: 'get',
        url: `${dojoHost}/api/v2/products/?name=${productName}`,
        headers: {
            'accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': `Token ${authToken}`
        }
    };

    const response = await axios(config);
    if (exactFirstByExactMatch) {
        return response.data.results.filter(p => p.name === productName)[0];
    }
    return response.data.results;
}

async function defectdojoCreateProduct(productName, productType, productDescription) {
    console.log(`Creating defectdojo product: ${productName}`)
    if (!productDescription) productDescription = productName;
    if (!productType) {
        console.warn("product type is not provided hence set it as 1 by default")
        productType = 1
    }
    var data = JSON.stringify({
        "name": productName,
        "prod_type": productType,
        "description": productDescription
    });

    var config = {
        method: 'post',
        url: `${dojoHost}/api/v2/products/`,
        headers: {
            'accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': `Token ${authToken}`,
        },
        data: data
    };

    const response = await axios(config);
    return response.data;
}

async function defectdojoGetEngagementsByName(engagementName, productId, getFirstByExactMatch) {
    const productFilter = productId ? `&product=${productId}` : "";
    var config = {
        method: 'get',
        url: `${dojoHost}/api/v2/engagements/?name=${engagementName}${productFilter}`,
        headers: {
            'accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': `Token ${authToken}`
        }
    };

    const response = await axios(config);
    if (getFirstByExactMatch) {
        return response.data.results.filter(e => e.name === engagementName)[0];
    }
    return response.data.results;
}


async function defectdojoCreateEngagement(engagementName, productId, startDate, endDate) {
    console.log(`Creating defectdojo engagement: ${engagementName}`)

    var data = JSON.stringify({
        "name": engagementName,
        "target_start": startDate ?? "2023-01-19",
        "target_end": endDate ?? "2023-01-26",
        "product": productId
    });

    var config = {
        method: 'post',
        url: `${dojoHost}/api/v2/engagements/`,
        headers: {
            'accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': `Token ${authToken}`,
        },
        data: data
    };

    const response = await axios(config);
    return response.data;
}

function funprogress() {
    let dots = ''
    process.stdout.write(`Loading `)

    let tmrID = setInterval(() => {
        dots += '.'
        process.stdout.write(`\rLoading ${dots}`)
    }, 1000)

    setTimeout(() => {
        clearInterval(tmrID)
        console.log(`\rLoaded in [3500 ms]`)
    }, 3500)
}

function generageCloudSploitConfigFile (scanConfigs,filepath) {
    const cloudsploitConfigServices = scanConfigs.scans.cloudsploit.services;
    // scanConfigCredentials
    const scc = scanConfigs.credentials;
    const credentials = {};
    const credTemplate = {
        aws: {
            access_key: scc.aws.accessKey,
            secret_access_key: scc.aws.secretAccessKey,
            session_token: scc.aws.sessionToken,
            plugins_remediate: ['bucketEncryptionInTransit']
        },
        aws_remediate: {
            access_key: scc.aws.accessKey,
            secret_access_key: scc.aws.secretAccessKey,
            session_token: scc.aws.sessionToken,
        },
        azure: {
            application_id: scc.azure.applicationID,
            key_value: scc.azure.keyValue,
            directory_id: scc.azure.directoryID,
            subscription_id: scc.azure.subscriptionID
        },
        google: {
            project: scc.google.project,
            client_email: scc.google.clientEmail,
            private_key: scc.google.privateKey
        },
        oracle: {
            tenancy_id: scc.oracle.tenancyId,
            compartment_id: scc.oracle.compartmentId,
            user_id: scc.oracle.userId,
            key_fingerprint: scc.oracle.keyFingerprint,
            key_value: scc.oracle.keyValue
        },
        github: {
            token: scc.github.token,
            url: scc.github.url,
            login: scc.github.login,
            organization: scc.github.organization
        }

    }

    credentials.azure = cloudsploitConfigServices.azure ? credTemplate.azure : {};
    credentials.azure_remediate = cloudsploitConfigServices.azure_remediate ? credTemplate.azure : {};
    credentials.aws = cloudsploitConfigServices.aws ? credTemplate.aws : {};
    credentials.aws_remediate = cloudsploitConfigServices.aws_remediate ? credTemplate.aws_remediate : {};
    credentials.google = cloudsploitConfigServices.google ? credTemplate.google : {};
    credentials.google_remediate = cloudsploitConfigServices.google_remediate ? credTemplate.google : {};
    credentials.oracle = cloudsploitConfigServices.oracle ? credTemplate.oracle : {};
    credentials.github = cloudsploitConfigServices.github ? credTemplate.github : {};


    const fileOut = `module.exports = { \
        credentials: ${JSON.stringify(credentials, null, 2)}\
    }`;
    
    fs.writeFileSync(filepath, fileOut);

}

async function executeScans() {
    validateConfigs();
    validateArguments();
    
    console.log(`Cloud Scan for product '${productName}'`)

    const engagementName = 'DefaultEngament'
    const reportsDirectory = `${profileRootDir}/${productName}/${profileReportsDirName}/${engagementName}`;
    const cloudSploitReportsPath = `${reportsDirectory}/cloudsploits`
    const configFilePath = `${cloudSploitReportsPath}/cloud-sploit-config.js`;
    // const configFilePath = `${cloudSploitRootDir}/../configs/config.js`;
    const cloudPloitOutputPath = `${cloudSploitReportsPath}/cloudsploit_scan_raw_report.json`
    const CloudSploitEnhancedOutputPath = `${cloudSploitReportsPath}/cloudsploit_scan_enhanced_report.json`
    
    
    try {
        mkDirIfNotExist(cloudSploitReportsPath);
        // generageCloudSploitConfigFile(scanConfigs,configFilePath);
        // await executeCloudSploitScan(configFilePath, cloudPloitOutputPath);
        // await enhanceCloudSploitResult(cloudPloitOutputPath, CloudSploitEnhancedOutputPath);
        console.log(`Target Dojo host: ${dojoHost}`)
        console.log(`process.env.NODE_ENV: ${process.env.NODE_ENV}`)
        console.log(`config.util.getEnv(): ${config.util.getEnv('NODE_ENV')}`)
        await defectDojoAuthenticate();
        let product = await defectdojoGetProductsByName(productName, true);
        if (!product) {
            console.info(`Product with name ${productName} is not currently exist`)
            product = await defectdojoCreateProduct(productName);
        }
        const engagement = await defectdojoGetEngagementsByName(engagementName, product.id, true);
        if (!engagement) {
            console.info(`Engagement with name ${engagementName} is not currently exist`)
            await defectdojoCreateEngagement(engagementName, product.id)
        }
        await defectdojoImportScan(productName, engagementName, CloudSploitEnhancedOutputPath);
    } catch (error) {
        console.error(error.message);
        console.error(error)
    } finally {
        //Delete temp files
        if (fs.existsSync(configFilePath)) {
            fs.unlinkSync(configFilePath)
        }
    }

}

executeScans();