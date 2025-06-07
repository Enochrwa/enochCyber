
import React, { useEffect, lazy, useState, Suspense } from "react";

import { BrowserRouter, Routes, Route } from "react-router-dom";
import Index from "./pages/Index";

// const  Dashboard = lazy(() => import("./pages/Dashboard"));
// const Threats = lazy(() => import("./pages/Threats"));
// const  Network = lazy(() => import( "./pages/Network"));
// const Logs = lazy(() =>import("./pages/Logs"));
// const  Models = lazy(() => import("./pages/Models"));
// const  System = lazy(() => import("./components/live-system/System"));
// const  Users = lazy(() => import("./pages/Users"));
// const  Settings = lazy(() => import("./pages/Settings"));
// const  AttackSimulations = lazy(() => import("./pages/AttackSimulations"));

import Dashboard from "./pages/Dashboard";
import Threats from "./pages/Threats";
import Network from "./pages/Network";
import Logs from "./pages/Logs";
import Models from "./pages/Models";
import System from "./components/live-system/System";
import Users from "./pages/Users";
import Settings from "./pages/Settings";
import AttackSimulations from "./pages/AttackSimulations";

import MainLayout from "./components/layout/MainLayout";
import NotFound from "./pages/NotFound";


import { ThreatCve } from "./pages/threats/ThreatCve";
import { ThreatMitre } from "./pages/threats/ThreatMitre";
import { ThreatIntel } from "./pages/threats/ThreatIntel";
import { ThreatOsint } from "./pages/threats/ThreatOsint";
import Alerts from "./alert/Alerts";
// import useSocket from "./hooks/useSocket"; // Assuming this is not the primary socket hook for app connectivity status
import usePacketSniffer from "./hooks/usePacketSnifferSocket";
import CyberLoader from "./utils/Loader"
import AuthModal from "./pages/AuthModal";
import { useSelector } from "react-redux"
import { RootState } from "@/app/store"

const App = () => {
  const { isConnected, connectionError, socket } = usePacketSniffer();
  // const { isConnected: otherSocketConnected, ... } = useSocket(); // If using multiple sockets and need to check all
  

  // useEffect(() => {
  //   if (!isConnected) {
  //     const interval = setInterval(() => {
  //       window.location.reload();
  //     }, 30000); // 30 seconds
  
  //     // Clear the interval if the component unmounts or connection is established
  //     return () => clearInterval(interval);
  //   }
  // }, [isConnected]);
  
  // Apply theme on initial load

  const [progress, setProgress] = useState(0); // For the progress bar (0–100%)
  const [isReady, setIsReady] = useState(false); // To know if the server is fully ready
  const [startupTime, setStartupTime] = useState("");
  const isBackendUp = useSelector((state:RootState) => state.display.isBackendUp)


  useEffect(() => {
    if (socket) {
        // socket.on("startup_progress", ({ elapsed_time }) => {
        //   setProgress(Math.min((elapsed_time / 20) * 100, 100));  // assumes max 20s
        // });
      
        socket.on("server_ready", ({ startup_time }) => {
          // setProgress(100);
          setIsReady(true);
          // setStartupTime(startup_time.toFixed(2));
          // window.location.reload(); // Commented out: This can cause post-login redirection issues.
          console.log("Server is ready, startup time:", startup_time); // Log instead of reload
        });
    }
  },[socket]);

  useEffect(() => {
    const root = window.document.documentElement;
    const theme = localStorage.getItem('theme') || 'system';
    
    if (theme === 'system') {
      const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches
        ? 'dark'
        : 'light';
      root.classList.add(systemTheme);
    } else {
      root.classList.add(theme);
    }
  }, []);

  // if (!isConnected) {
  //   return (
  //     <ThemeProvider defaultTheme="system" storageKey="theme">
  //       <div className="flex flex-col items-center justify-center min-h-screen bg-background text-foreground p-4">
  //         <div className="text-center">
  //           <Loader2 className="h-12 w-12 animate-spin text-isimbi-purple mx-auto mb-4" />
  //           <h1 className="text-2xl font-semibold mb-2">Connecting to eCyber Server...</h1>
  //           {connectionError ? (
  //             <p className="text-sm text-red-500 dark:text-red-400 max-w-md">
  //               {connectionError}
  //             </p>
  //           ) : (
  //             <p className="text-sm text-muted-foreground">
  //               Please wait while we establish a connection.
  //               {retryAttempts > 0 && ` (Attempt ${retryAttempts})`}
  //             </p>
  //           )}
  //           {/* Optionally, add a manual retry button if all retries fail */}
  //           {/* Or a button to go to a status page / contact support */}
  //         </div>
  //       </div>
  //     </ThemeProvider>
  //   );
  // }

  // if(!isReady || !isBackendUp) {
  //   return <CyberLoader isLoading={isReady || isBackendUp} />
  // }

  

  return (
    <>
      {/* <Suspense fallback={<LoadingSpinner />}> */}
        <Routes>
        {/* Public route without sidebar */}
          <Route path="/" element={<Index />} /> {/* Index page, handles showing AuthModal via button clicks */}
        <Route path="/loading" element={<CyberLoader />} />
  
          {/* Removed top-level /login route that pointed to AuthModal */}
          {/* Routes with sidebar, potentially protected by MainLayout */}
          <Route element={<MainLayout />}>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/system" element={<System/>} />
            <Route path="/alerts" element={<Alerts/>} />
            <Route path="/threats" element={<Threats />} />
            <Route path="/network" element={<Network />} />
            <Route path="/logs" element={<Logs />} />
            <Route path="/models" element={<Models />} />
            {/* Removed /login and /register routes that pointed to LoginPage and RegisterPage */}
            <Route path="/users" element={<Users />} />
            <Route path="/threats/cve" element={<ThreatCve />} />
            <Route path="/threats/intel" element={<ThreatIntel />} />
            <Route path="/threats/mitre" element={<ThreatMitre />} />
            <Route path="/threats/osint" element={<ThreatOsint />} />
            
            <Route path="/settings" element={<Settings />} />
            <Route path="/attack-simulations" element={<AttackSimulations />} />
          </Route>

          {/* 404 Page */}
          <Route path="*" element={<NotFound />} />
        </Routes>
        <AuthModal /> {/* Ensure AuthModal is rendered globally */}
        {/* </Suspense> */}
     </>
  );
};




export default App;
