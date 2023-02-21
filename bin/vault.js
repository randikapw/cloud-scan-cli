import { DefaultAzureCredential } from "@azure/identity";
import { SecretClient } from "@azure/keyvault-secrets";
import config from "config";



function _getSecretCleint() {
    const credential = new DefaultAzureCredential();

    const keyVaultName = config.get("azure.keyVault.name");
    const url = "https://" + keyVaultName + ".vault.azure.net";

    return new SecretClient(url, credential);
}

async function setSecret(secretName, value) {
    if (!secretName) {
        throw new Error("secretName cannot be empty");
    }
    else if (secretName.endsWith('_long')) {
        const msg = `Invalied secretName '${secretName}'. '_long' postfix is reserved by the internal functions.`
        throw new Error(msg)
    }
    else {
        const client = _getSecretCleint();
        console.debug(`setValueto Vault with length ${value.length}`)
        const result = await client.setSecret(secretName, value);
        // console.debug("result: ", result);
    }
}

async function getSecret(secretName) {
    const client = _getSecretCleint();



    // Read the secret we created
    const secret = await client.getSecret(secretName);
    //console.debug("secret: ", secret);
    return secret.value;
    // // Update the secret with different attributes
    // const updatedSecret = await client.updateSecretProperties(secretName, result.properties.version, {
    //     enabled: false
    // });
    // console.debug("updated secret: ", updatedSecret);

    // // Delete the secret
    // // If we don't want to purge the secret later, we don't need to wait until this finishes
    // await client.beginDeleteSecret(secretName);
}

export default {
    setSecret,
    getSecret
}
