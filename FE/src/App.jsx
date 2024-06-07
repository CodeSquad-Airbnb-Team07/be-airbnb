import { BrowserRouter, Routes, Route } from "react-router-dom";
import Layout from "./components/global/layout";
import LoginPage from "./pages/loginPage";
import IntroductionPage from "./pages/inroduction";
import RedirectPage from "./services/redirect.jsx";

const App = () => {
  return (
    <div className="App">
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<IntroductionPage />} />
            <Route path="/login" element={<LoginPage />} />
            <Route
              path="/oauth/redirected/github"
              element={<RedirectPage provider="github" />}
            />
            <Route
              path="/oauth/redirected/google"
              element={<RedirectPage provider="google" />}
            />
          </Route>
        </Routes>
      </BrowserRouter>
    </div>
  );
};

export default App;
