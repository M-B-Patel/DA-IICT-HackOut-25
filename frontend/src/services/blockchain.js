import axios from 'axios';

const API_BASE_URL = '/api';

export const blockchainAPI = {
  getChain: () => axios.get(`${API_BASE_URL}/chain`),
  mineBlock: () => axios.post(`${API_BASE_URL}/mine`),
  createTransaction: (transactionData) => 
    axios.post(`${API_BASE_URL}/transactions/new`, transactionData),
  getPendingTransactions: () => axios.get(`${API_BASE_URL}/pending_transactions`),
  getWalletInfo: () => axios.get(`${API_BASE_URL}/wallet/info`),
  registerNodes: (nodes) => 
    axios.post(`${API_BASE_URL}/nodes/register`, { nodes }),
  resolveConflicts: () => axios.get(`${API_BASE_URL}/nodes/resolve`)
};