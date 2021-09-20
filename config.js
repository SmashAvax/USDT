require('dotenv').config()

module.exports = {
  deployments: {
    netId1: {
      usdt: {
        instanceAddress: {
          '1': '',
          '100': '',
          '1000': '',
          '10000': ''
        },
        tokenAddress: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
        symbol: 'USDT',
        decimals: 6
      }
    },
    netId42: {
      usdt: {
        instanceAddress: {
          '1': '',
          '100': '',
          '1000': '',
          '10000': ''
        },
        tokenAddress: '0x13512979ade267ab5100878e2e0f485b568328a4',
        symbol: 'USDT',
        decimals: 6
      }
    }
  }
}
