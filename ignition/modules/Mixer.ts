// This setup uses Hardhat Ignition to manage smart contract deployments.
// Learn more about it at https://hardhat.org/ignition

import { ethers } from "hardhat"
import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
// import { poseidonContract } from "circomlibjs"

const MixerDeployment = buildModule("MixerDeployment", (m) => {
    // get deployer account
    const deployer = m.getAccount(0);

    // deploy poseidon contract with circomlibjs
    // const nInput = 2
    // const byteCode = poseidonContract.createCode(nInput)
    // const abi = poseidonContract.generateABI(nInput)

    // deploy poseidon contract
    // const poseidon = m.contract("Poseidon", [], { from: deployer });

    // deploy verifier contracts
    const verifier = m.contract("Groth16Verifier", [], { from: deployer });

    const token = "0x686c5961370db7f14f57f5a430e05deae64df504"

    // deploy mixer contract
    const mixer = m.contract("AintiVirusMixer", [token, verifier, deployer], { from: deployer });

    console.log("✅ Contracts deployed by:", deployer);

    return { verifier, mixer };
});

export default MixerDeployment;
