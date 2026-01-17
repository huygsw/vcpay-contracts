const dotenv = require("dotenv");

dotenv.config();

// require("tsconfig-paths/register");
// require("@nomiclabs/hardhat-waffle");
// require("@nomicfoundation/hardhat-verify");
// require("@openzeppelin/hardhat-upgrades");
// require("hardhat-gas-reporter");

require("hardhat-gas-reporter");
require("@nomiclabs/hardhat-ethers");
require("@nomiclabs/hardhat-etherscan");
require("@openzeppelin/hardhat-upgrades");

module.exports = {
  // paths: {
  //   sources: "./contracts/v2", // Specify the contracts folder
  // },
  solidity: {
    compilers: [
      {
        version: "0.8.20",
        settings: {
          optimizer: {
            enabled: true,
            runs: 600,
          },
        },
      },
      {
        version: "0.8.22",
        settings: {
          optimizer: {
            enabled: true,
            runs: 600,
          },
        },
      },
      {
        version: "0.8.27",
        settings: {
          optimizer: {
            enabled: true,
            runs: 600,
          },
        },
      },
      {
        version: "0.8.29",
        settings: {
          optimizer: {
            enabled: true,
            runs: 600,
          },
        },
      },
    ],
  },
  gasReporter: {
    currency: "USD",
  },
  etherscan: {
    apiKey: {
      bsc: process.env.BSCAN_API_KEY,
      bscTestnet: process.env.BSCAN_API_KEY,
    },
  },
  sourcify: {
    enabled: false,
  },
  networks: {
    bsc: {
      url: process.env.QUICK_NODE_HTTP_PROVIDER_URL,
      accounts: [process.env.PRIVATE_KEY],
      gas: 3000000,
      gasPrice: "auto",
    },
    bscTestnet: {
      url: process.env.QUICK_NODE_HTTP_PROVIDER_URL,
      accounts: [process.env.PRIVATE_KEY],
      gas: 3000000,
      gasPrice: "auto",
    },
  },
};
