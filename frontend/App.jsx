import React, { useState, useEffect } from 'react';
import { Container, Typography, Tabs, Tab, Box } from '@mui/material';
import { Dashboard } from './components/Dashboard';
import { TransactionForm } from './components/TransactionForm';
import { MiningInterface } from './components/MiningInterface';
import { NodeManagement } from './components/NodeManagement';
import { blockchainAPI } from './services/blockchain';

function TabPanel(props) {
  const { children, value, index, ...other } = props;
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

function App() {
  const [tabValue, setTabValue] = useState(0);
  const [blockchainData, setBlockchainData] = useState({ chain: [], length: 0 });
  const [walletInfo, setWalletInfo] = useState({ address: '', balance: 0 });

  const handleTabChange = (event, newValue) => {
    setTabValue(newValue);
  };

  const refreshBlockchainData = async () => {
    try {
      const response = await blockchainAPI.getChain();
      setBlockchainData(response.data);
    } catch (error) {
      console.error('Error fetching blockchain data:', error);
    }
  };

  const refreshWalletInfo = async () => {
    try {
      const response = await blockchainAPI.getWalletInfo();
      setWalletInfo(response.data);
    } catch (error) {
      console.error('Error fetching wallet info:', error);
    }
  };

  useEffect(() => {
    refreshBlockchainData();
    refreshWalletInfo();
    
    // Refresh data every 10 seconds
    const interval = setInterval(() => {
      refreshBlockchainData();
      refreshWalletInfo();
    }, 10000);
    
    return () => clearInterval(interval);
  }, []);

  return (
    <Container maxWidth="lg">
      <Typography variant="h3" component="h1" gutterBottom align="center" sx={{ mt: 3 }}>
        GHC Blockchain Interface
      </Typography>
      
      <Typography variant="h6" gutterBottom>
        Wallet: {walletInfo.address.substring(0, 20)}... | Balance: {walletInfo.balance} GHC
      </Typography>
      
      <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Tabs value={tabValue} onChange={handleTabChange}>
          <Tab label="Dashboard" />
          <Tab label="Create Transaction" />
          <Tab label="Mining" />
          <Tab label="Node Management" />
        </Tabs>
      </Box>
      
      <TabPanel value={tabValue} index={0}>
        <Dashboard 
          blockchain={blockchainData} 
          onRefresh={refreshBlockchainData} 
        />
      </TabPanel>
      
      <TabPanel value={tabValue} index={1}>
        <TransactionForm 
          onTransactionCreated={() => {
            refreshBlockchainData();
            refreshWalletInfo();
          }} 
        />
      </TabPanel>
      
      <TabPanel value={tabValue} index={2}>
        <MiningInterface 
          onBlockMined={() => {
            refreshBlockchainData();
            refreshWalletInfo();
          }} 
        />
      </TabPanel>
      
      <TabPanel value={tabValue} index={3}>
        <NodeManagement />
      </TabPanel>
    </Container>
  );
}

export default App;