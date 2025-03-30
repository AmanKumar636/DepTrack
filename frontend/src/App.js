// src/App.js
import React, { useEffect, useState } from 'react';
import { Bar } from 'react-chartjs-2';
import {
  AppBar,
  Toolbar,
  IconButton,
  Typography,
  Container,
  Drawer,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  CssBaseline,
  Grid,
  Paper,
  Switch,
  Button,
  useMediaQuery,
} from '@mui/material';
import { Menu as MenuIcon, Dashboard as DashboardIcon, Refresh as RefreshIcon } from '@mui/icons-material';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { SnackbarProvider, useSnackbar } from 'notistack';
import { motion } from 'framer-motion';
import logo from './assets/logo.png';

const drawerWidth = 240;

// Define light and dark themes.
const getTheme = (darkMode) =>
  createTheme({
    palette: {
      mode: darkMode ? 'dark' : 'light',
      primary: {
        main: darkMode ? '#90caf9' : '#1976d2',
      },
      secondary: {
        main: darkMode ? '#f48fb1' : '#dc004e',
      },
      background: {
        default: darkMode ? '#121212' : '#f4f6f8',
      },
    },
    typography: {
      fontFamily: 'Roboto, sans-serif',
      h4: {
        fontWeight: 600,
      },
    },
  });

// A component to show scan notifications via Snackbar.
function ScanNotifier({ scanResults }) {
  const { enqueueSnackbar } = useSnackbar();

  useEffect(() => {
    if (scanResults) {
      enqueueSnackbar(`Scan updated: ${scanResults.summary}`, { variant: 'info' });
    }
  }, [scanResults, enqueueSnackbar]);

  return null;
}

function App() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [darkMode, setDarkMode] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const isSmallScreen = useMediaQuery('(max-width:600px)');

  const theme = getTheme(darkMode);

  // Use the environment variable or default to localhost for local testing.
  const backendUrl = process.env.REACT_APP_BACKEND_URL || "http://localhost:3001";

  const fetchScanResults = () => {
    fetch(`${backendUrl}/api/scan`)
      .then(res => res.json())
      .then(data => setScanResults(data))
      .catch(err => console.error("Error fetching scan results:", err));
  };

  // Fetch Snyk project data from your secure backend endpoint.
  const fetchSnykProjectData = () => {
    fetch(`${backendUrl}/api/snyk/project-data/your-project-id`)
      .then(res => res.json())
      .then(data => console.log('Snyk Project Data:', data))
      .catch(err => console.error("Error fetching Snyk project data:", err));
  };

  useEffect(() => {
    fetchScanResults();
    fetchSnykProjectData();
  }, []);

  const handleDrawerToggle = () => {
    setMobileOpen(!mobileOpen);
  };

  // Prepare chart data (example: vulnerability counts by severity)
  const severityCounts = { low: 0, medium: 0, high: 0 };
  if (scanResults && Array.isArray(scanResults.vulnerabilities)) {
    scanResults.vulnerabilities.forEach(vuln => {
      const sev = vuln.severity.toLowerCase();
      if (severityCounts[sev] !== undefined) {
        severityCounts[sev] += 1;
      }
    });
  }
  const chartData = {
    labels: ["Low", "Medium", "High"],
    datasets: [{
      label: "Vulnerability Count",
      data: [severityCounts.low, severityCounts.medium, severityCounts.high],
      backgroundColor: ["#66bb6a", "#ffa726", "#ef5350"],
    }],
  };

  // Sidebar content
  const drawer = (
    <div>
      <Toolbar sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <img src={logo} alt="DepTrack Logo" style={{ width: 50, marginRight: 8 }} />
        <Typography variant="h6" noWrap>DepTrack</Typography>
      </Toolbar>
      <List>
        <ListItem button key="Dashboard">
          <ListItemIcon>
            <DashboardIcon />
          </ListItemIcon>
          <ListItemText primary="Dashboard" />
        </ListItem>
        {/* Add more navigation items here */}
      </List>
    </div>
  );

  return (
    <ThemeProvider theme={theme}>
      <SnackbarProvider maxSnack={3}>
        <CssBaseline />
        <ScanNotifier scanResults={scanResults} />
        <div style={{ display: 'flex' }}>
          {/* AppBar */}
          <AppBar position="fixed" sx={{ zIndex: (theme) => theme.zIndex.drawer + 1 }}>
            <Toolbar>
              <IconButton
                color="inherit"
                edge="start"
                onClick={handleDrawerToggle}
                sx={{ mr: 2, display: { sm: 'none' } }}
              >
                <MenuIcon />
              </IconButton>
              <Typography variant="h6" noWrap component="div" sx={{ flexGrow: 1 }}>
                DepTrack Dashboard
              </Typography>
              <Switch
                checked={darkMode}
                onChange={() => setDarkMode(!darkMode)}
                color="default"
                inputProps={{ 'aria-label': 'toggle dark mode' }}
              />
            </Toolbar>
          </AppBar>

          {/* Permanent Drawer for desktop */}
          <Drawer
            variant="permanent"
            sx={{
              width: drawerWidth,
              flexShrink: 0,
              [`& .MuiDrawer-paper`]: { width: drawerWidth, boxSizing: 'border-box' },
              display: { xs: 'none', sm: 'block' },
            }}
            open
          >
            {drawer}
          </Drawer>

          {/* Temporary Drawer for mobile */}
          <Drawer
            variant="temporary"
            open={mobileOpen}
            onClose={handleDrawerToggle}
            ModalProps={{ keepMounted: true }}
            sx={{
              display: { xs: 'block', sm: 'none' },
              [`& .MuiDrawer-paper`]: { boxSizing: 'border-box', width: drawerWidth },
            }}
          >
            {drawer}
          </Drawer>

          {/* Main Content */}
          <main style={{ flexGrow: 1, padding: theme.spacing(3) }}>
            <Toolbar />
            <Container maxWidth="lg">
              <Grid container spacing={4}>
                {/* Overview Card */}
                <Grid item xs={12}>
                  <Paper elevation={3} sx={{ padding: 3, textAlign: 'center', background: 'linear-gradient(45deg, #2196f3, #21cbf3)' }}>
                    <Typography variant="h4" color="white">
                      {scanResults ? scanResults.summary : "Loading scan results..."}
                    </Typography>
                    <Button
                      variant="contained"
                      startIcon={<RefreshIcon />}
                      sx={{ mt: 2 }}
                      onClick={fetchScanResults}
                    >
                      Refresh Scan
                    </Button>
                  </Paper>
                </Grid>

                {/* Chart Card */}
                <Grid item xs={12} md={6}>
                  <Paper elevation={3} sx={{ padding: 3 }}>
                    <Typography variant="h6" sx={{ mb: 2 }}>Vulnerability Severity Chart</Typography>
                    <Bar data={chartData} />
                  </Paper>
                </Grid>

                {/* Vulnerability Details Card */}
                <Grid item xs={12} md={6}>
                  <Paper elevation={3} sx={{ padding: 3, maxHeight: 500, overflow: 'auto' }}>
                    <Typography variant="h6" sx={{ mb: 2 }}>Vulnerability Details</Typography>
                    {scanResults && Array.isArray(scanResults.vulnerabilities) ? (
                      scanResults.vulnerabilities.map(vuln => (
                        <motion.div
                          key={vuln.id}
                          whileHover={{ scale: 1.02 }}
                          style={{ padding: '8px 0', borderBottom: '1px solid #e0e0e0' }}
                        >
                          <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                            {vuln.package} ({vuln.severity})
                          </Typography>
                          <Typography variant="body2" sx={{ color: '#757575' }}>
                            {vuln.recommendation}
                          </Typography>
                        </motion.div>
                      ))
                    ) : (
                      <Typography>No vulnerabilities to display.</Typography>
                    )}
                  </Paper>
                </Grid>
              </Grid>
            </Container>
          </main>
        </div>
      </SnackbarProvider>
    </ThemeProvider>
  );
}

export default App;
