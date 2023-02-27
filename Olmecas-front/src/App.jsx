import { useState } from "react";
import "./App.css";
import React from "react";
import { Dany } from "./WorkSpaces/Dany";
import { Esteban } from "./WorkSpaces/Esteban";
import { Jony } from "./WorkSpaces/Jony";

export const App = () => {

  return (
  <div>
    <Dany/>
    <Esteban/>
    <Jony/>

  </div>
    );
};
