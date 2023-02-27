import { useState } from "react";
import "./App.css";
import React from "react";

export const App = () => {
  fetch("https://jsonplaceholder.typicode.com/posts?_limit=10")
    .then((response) => response.json())
    .then((data) => console.log(data));

  return <div>Hello world</div>;
};
