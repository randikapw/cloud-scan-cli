import config from "config";
import axios from "axios";
import fs from "fs";
import FormData from "form-data"



const dojoHost = config.get("defectdojo.host");
const dojoUserName = config.get("defectdojo.credentials.username");
const dojoPass = config.get("defectdojo.credentials.password");

export default class DefectDojo {
    #authToken;
    #logger;

    static get host() {
        return dojoHost
    }

    constructor(logger) {
        this.#logger = logger;
    }

    async authenticate() {
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
        this.#authToken = result.data.token;
        return result.data;
    }

    async getProductsByName(productName, exactFirstByExactMatch) {
        var config = {
            method: 'get',
            url: `${dojoHost}/api/v2/products/?name=${productName}`,
            headers: {
                'accept': 'application/json',
                'Content-Type': 'application/json',
                'Authorization': `Token ${this.#authToken}`
            }
        };
    
        const response = await axios(config);
        if (exactFirstByExactMatch) {
            return response.data.results.filter(p => p.name === productName)[0];
        }
        return response.data.results;
    }

    async createProduct(productName, productType, productDescription) {
        this.#logger.info(`Creating defectdojo product: ${productName}`)
        if (!productDescription) productDescription = productName;
        if (!productType) {
            this.#logger.warn("product type is not provided hence set it as 1 by default")
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

    async getEngagementsByName(engagementName, productId, getFirstByExactMatch) {
        const productFilter = productId ? `&product=${productId}` : "";
        var config = {
            method: 'get',
            url: `${dojoHost}/api/v2/engagements/?name=${engagementName}${productFilter}`,
            headers: {
                'accept': 'application/json',
                'Content-Type': 'application/json',
                'Authorization': `Token ${this.#authToken}`
            }
        };
    
        const response = await axios(config);
        if (getFirstByExactMatch) {
            return response.data.results.filter(e => e.name === engagementName)[0];
        }
        return response.data.results;
    }

    async createEngagement(engagementName, productId, startDate, endDate) {
        this.#logger.info(`Creating defectdojo engagement: ${engagementName}`)
    
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

    async importScan(productName, engagementName, scanFilePath, scanType) {
        if (!scanType) scanType = 'Cloudsploit Scan';
        const fileSize = fs.statSync(scanFilePath).size;
        const readStream = fs.createReadStream(scanFilePath);
        let uploadedSize = 0;
        const logger = this.#logger;
        readStream.on('data', function (buffer) {
            var segmentLength = buffer.length;
    
            // Increment the uploaded data counter
            uploadedSize += segmentLength;
    
            // Display the upload percentage
            // logger.info("Progress:\t",((uploadedSize/zipSize*100).toFixed(2)+"%"));
            let progress = (uploadedSize / fileSize * 100).toFixed(2);
            process.stdout.write(`\rUploading file: ${progress}%`);
            if (progress >= 100) {
                logger.info("Upload completed, waiting for response after defining all issues.. this may take few minutes...")
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
    
        this.#logger.info(`Improt scan resutls for scan type '${scanType}' to the product '${productName}' under engagement '${engagementName}'`)
        var config = {
            method: 'post',
            url: `${dojoHost}/api/v2/import-scan/`,
            headers: {
                'accept': 'application/json',
                'Authorization': `Token ${this.#authToken}`,
                ...data.getHeaders()
            },
            //onUploadProgress: progressEvent => process.stdout.write(`\nImporting ${progressEvent.loaded}`),
            data: data
        };
    
        // axios(config)
        //     .then(function (response) {
        //         this.#logger.info('Import Scan completed');
        //         this.#logger.info(JSON.stringify(response.data));
        //     })
        //     .catch(function (error) {
        //         this.#logger.info(error);
        //     });
        const response = await axios(config)
        this.#logger.info('Import Scan completed');
        this.#logger.info(JSON.stringify(response.data));
    }
}