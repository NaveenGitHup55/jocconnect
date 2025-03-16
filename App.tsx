import { Switch, Route, useLocation } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import NotFound from "@/pages/not-found";
import Home from "@/pages/Home";
import Login from "@/pages/Login";
import Register from "@/pages/Register";
import PostJob from "@/pages/PostJob";
import Profile from "@/pages/Profile";
import { AuthProvider } from "@/lib/auth";
import Header from "@/components/Header";
import MobileNav from "@/components/MobileNav";
import ChatWidget from "@/components/ChatWidget";

function Router() {
  const [location] = useLocation();
  
  // Don't show header on login/register pages
  const hideHeaderRoutes = ['/login', '/register'];
  const shouldShowHeader = !hideHeaderRoutes.includes(location);
  
  return (
    <div className="min-h-screen flex flex-col">
      {shouldShowHeader && <Header />}
      
      <Switch>
        <Route path="/" component={Home} />
        <Route path="/login" component={Login} />
        <Route path="/register" component={Register} />
        <Route path="/post-job" component={PostJob} />
        <Route path="/profile" component={Profile} />
        <Route component={NotFound} />
      </Switch>
      
      {shouldShowHeader && <MobileNav />}
      
      {/* Floating Action Button (Mobile) */}
      {shouldShowHeader && (
        <div className="md:hidden fixed right-4 bottom-20 z-50">
          <a href="/post-job" className="w-14 h-14 rounded-full bg-primary text-white shadow-lg flex items-center justify-center">
            <i className="fas fa-plus text-xl"></i>
          </a>
        </div>
      )}
    </div>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <Router />
        <ChatWidget />
        <Toaster />
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;
