// This setup uses Hardhat Ignition to manage smart contract deployments.
// Learn more about it at https://hardhat.org/ignition

import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

const TokenDeployment = buildModule("TokenDeployment", (m) => {
    // get deployer account
    const deployer = m.getAccount(0);

    // deploy token contract
    const token = m.contract("ERC20Standard", ["Ainti Virus Token", "AINTI"])

    console.log("✅ Contracts deployed by:", deployer);

    return { token };
});

export default TokenDeployment;
