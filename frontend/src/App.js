import React, { useEffect, useState } from 'react';
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
  Card,
  CardContent,
  CardHeader,
  CardActions,
  Button,
  Switch,
  Divider,
  useMediaQuery,
  Box,
} from '@mui/material';
import {
  Menu as MenuIcon,
  Dashboard as DashboardIcon,
  Refresh as RefreshIcon,
  BugReport as BugReportIcon,
} from '@mui/icons-material';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { SnackbarProvider, useSnackbar } from 'notistack';
import { Bar } from 'react-chartjs-2';
import { motion } from 'framer-motion';
import logo from './assets/logo.png';

const drawerWidth = 240;

const getTheme = (darkMode) =>
  createTheme({
    palette: {
      mode: darkMode ? 'dark' : 'light',
      primary: { main: darkMode ? '#90caf9' : '#1976d2' },
      secondary: { main: darkMode ? '#f48fb1' : '#dc004e' },
      background: { default: darkMode ? '#121212' : '#f4f6f8' },
    },
    typography: { fontFamily: 'Roboto, sans-serif', h4: { fontWeight: 600 }, h6: { fontWeight: 600 } },
  });

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
  const theme = getTheme(darkMode);
  const isSmallScreen = useMediaQuery('(max-width:600px)');
  const backendUrl = process.env.REACT_APP_BACKEND_URL || "http://localhost:3001";

  const fetchScanResults = async () => {
    try {
      const res = await fetch(`${backendUrl}/api/scan?timestamp=${new Date().getTime()}`);
      const data = await res.json();
      console.log("Fetched scan result:", data);
      // Ensure arrays are defined.
      data.vulnerabilities = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];
      data.outdated = Array.isArray(data.outdated) ? data.outdated : [];
      data.licenseIssues = Array.isArray(data.licenseIssues) ? data.licenseIssues : [];
      setScanResults(data);
    } catch (err) {
      console.error("Error fetching scan results:", err);
    }
  };

  const fetchSnykProjectData = async () => {
    try {
      const res = await fetch(`${backendUrl}/api/snyk/project-data/d6b39f1b-82aa-4fbe-923f-643e00124c2c`);
      const data = await res.json();
      console.log("Snyk Project Data:", data);
    } catch (err) {
      console.error("Error fetching Snyk project data:", err);
    }
  };

  useEffect(() => {
    fetchScanResults();
    fetchSnykProjectData();
  }, []);

  const handleDrawerToggle = () => setMobileOpen(!mobileOpen);
  const debugScanResults = () => console.log("Current scan results:", scanResults);

  // Prepare chart data for vulnerability severity.
  const severityCounts = { low: 0, medium: 0, high: 0 };
  if (scanResults && Array.isArray(scanResults.vulnerabilities)) {
    scanResults.vulnerabilities.forEach((vuln) => {
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

  const drawer = (
    <div>
      <Toolbar sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <img src={logo} alt="DepTrack Logo" style={{ width: 50, marginRight: 8 }} />
        <Typography variant="h6" noWrap>DepTrack</Typography>
      </Toolbar>
      <List>
        <ListItem button key="Dashboard">
          <ListItemIcon><DashboardIcon /></ListItemIcon>
          <ListItemText primary="Dashboard" />
        </ListItem>
      </List>
    </div>
  );

  return (
    <ThemeProvider theme={theme}>
      <SnackbarProvider maxSnack={3}>
        <CssBaseline />
        <ScanNotifier scanResults={scanResults} />
        <div style={{ display: 'flex' }}>
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
              <Typography variant="h6" noWrap sx={{ flexGrow: 1 }}>
                DepTrack Dashboard
              </Typography>
              <Switch
                checked={darkMode}
                onChange={() => setDarkMode(!darkMode)}
                color="default"
                inputProps={{ 'aria-label': 'toggle dark mode' }}
              />
              <Button variant="contained" startIcon={<RefreshIcon />} onClick={fetchScanResults} sx={{ ml: 2 }}>
                Refresh Scan
              </Button>
              <Button variant="outlined" startIcon={<BugReportIcon />} onClick={debugScanResults} sx={{ ml: 1 }}>
                Debug
              </Button>
            </Toolbar>
          </AppBar>

          {/* Permanent Drawer for Desktop */}
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

          {/* Temporary Drawer for Mobile */}
          <Drawer
            variant="temporary"
            open={mobileOpen}
            onClose={handleDrawerToggle}
            ModalProps={{ keepMounted: true }}
            sx={{
              display: { xs: 'block', sm: 'none' },
              [`& .MuiDrawer-paper`]: { width: drawerWidth, boxSizing: 'border-box' },
            }}
          >
            {drawer}
          </Drawer>

          <main style={{ flexGrow: 1, padding: theme.spacing(3), marginTop: 64 }}>
            <Container maxWidth="lg">
              <Grid container spacing={4}>
                {/* Overview Card */}
                <Grid item xs={12}>
                  <Card elevation={4} sx={{ background: 'linear-gradient(45deg, #2196f3, #21cbf3)', color: 'white' }}>
                    <CardHeader title="Scan Overview" />
                    <CardContent>
                      <Typography variant="h5">
                        {scanResults ? scanResults.summary : "Loading scan results..."}
                      </Typography>
                      {scanResults && (
                        <Typography variant="caption" display="block">
                          Last updated: {new Date(scanResults.timestamp).toLocaleString()}
                        </Typography>
                      )}
                    </CardContent>
                    <CardActions>
                      <Button variant="contained" startIcon={<RefreshIcon />} onClick={fetchScanResults}>
                        Refresh Scan
                      </Button>
                    </CardActions>
                  </Card>
                </Grid>

                {/* Vulnerability Severity Chart */}
                <Grid item xs={12} md={6}>
                  <Card elevation={4}>
                    <CardHeader title="Vulnerability Severity" />
                    <CardContent>
                      <Bar data={chartData} />
                    </CardContent>
                  </Card>
                </Grid>

                {/* Vulnerability Details */}
                <Grid item xs={12} md={6}>
                  <Card elevation={4}>
                    <CardHeader title="Vulnerability Details" />
                    <CardContent>
                      {scanResults && scanResults.vulnerabilities.length > 0 ? (
                        scanResults.vulnerabilities.map((vuln) => (
                          <Box key={vuln.id} mb={2}>
                            <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                              {vuln.package} ({vuln.severity})
                            </Typography>
                            <Typography variant="body2" color="textSecondary">
                              {vuln.recommendation}
                            </Typography>
                            <Divider sx={{ my: 1 }} />
                          </Box>
                        ))
                      ) : (
                        <Typography>No vulnerabilities to display.</Typography>
                      )}
                    </CardContent>
                  </Card>
                </Grid>

                {/* Outdated Dependencies */}
                <Grid item xs={12} md={6}>
                  <Card elevation={4}>
                    <CardHeader title="Outdated Dependencies" />
                    <CardContent>
                      {scanResults && scanResults.outdated.length > 0 ? (
                        scanResults.outdated.map((dep) => (
                          <Box key={dep.package} mb={2}>
                            <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                              {dep.package}
                            </Typography>
                            <Typography variant="body2" color="textSecondary">
                              Current: {dep.currentVersion} | Latest: {dep.latestVersion}
                            </Typography>
                            <Typography variant="body2" color="textSecondary">
                              {dep.recommendation}
                            </Typography>
                            <Divider sx={{ my: 1 }} />
                          </Box>
                        ))
                      ) : (
                        <Typography>No outdated dependencies to display.</Typography>
                      )}
                    </CardContent>
                  </Card>
                </Grid>

                {/* License Issues */}
                <Grid item xs={12} md={6}>
                  <Card elevation={4}>
                    <CardHeader title="License Issues" />
                    <CardContent>
                      {scanResults && scanResults.licenseIssues.length > 0 ? (
                        scanResults.licenseIssues.map((issue) => (
                          <Box key={issue.package} mb={2}>
                            <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                              {issue.package}
                            </Typography>
                            <Typography variant="body2" color="textSecondary">
                              License: {issue.license}
                            </Typography>
                            <Typography variant="body2" color="textSecondary">
                              {issue.recommendation}
                            </Typography>
                            <Divider sx={{ my: 1 }} />
                          </Box>
                        ))
                      ) : (
                        <Typography>No license issues to display.</Typography>
                      )}
                    </CardContent>
                  </Card>
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
