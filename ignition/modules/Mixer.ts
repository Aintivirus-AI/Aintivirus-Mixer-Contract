// This setup uses Hardhat Ignition to manage smart contract deployments.
// Learn more about it at https://hardhat.org/ignition

import { ethers } from "hardhat"
import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import { poseidonContract } from "circomlibjs"

const MixerDeployment = buildModule("MixerDeployment", (m) => {
    // get deployer account
    const deployer = m.getAccount(0);

    // deploy poseidon contract with circomlibjs
    // const nInput = 2
    // const byteCode = poseidonContract.createCode(nInput)
    // const abi = poseidonContract.generateABI(nInput)

    // deploy poseidon contract
    const poseidon = m.contract("Poseidon", [], { from: deployer });

    // deploy verifier contracts
    const verifier1 = m.contract("Groth16Verifier1", [], { from: deployer });
    const verifier2 = m.contract("Groth16Verifier2", [], { from: deployer });

    // deploy mixer contract
    const mixer = m.contract("AintiVirusMixer", [verifier1, verifier2, poseidon], { from: deployer });

    console.log("✅ Contracts deployed by:", deployer);

    return { verifier1, verifier2, mixer };
});

export default MixerDeployment;
