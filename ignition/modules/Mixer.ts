// This setup uses Hardhat Ignition to manage smart contract deployments.
// Learn more about it at https://hardhat.org/ignition

import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

const MixerDeployment = buildModule("MixerDeployment", (m) => {
    // get deployer account
    const deployer = m.getAccount(0);

    // deploy verifier contract
    const verifier = m.contract("Groth16Verifier", [], { from: deployer });

    // deploy mixer contract
    const mixer = m.contract("AintiVirusMixer", [verifier], { from: deployer });

    console.log("✅ Contracts deployed by:", deployer);

    return { verifier, mixer };
});

export default MixerDeployment;
