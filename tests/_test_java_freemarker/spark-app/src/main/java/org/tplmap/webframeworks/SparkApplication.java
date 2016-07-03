package org.tplmap.webframeworks;

import spark.ModelAndView;
import spark.Request;
import spark.Response;
import spark.template.thymeleaf.ThymeleafTemplateEngine;

import java.util.HashMap;
import java.util.Map;

import static spark.Spark.get;

public class SparkApplication {

  public static void main(String[] args) {

    get("/hello", SparkApplication::helloWorld, new ThymeleafTemplateEngine());
  }

  public static ModelAndView helloWorld(Request req, Response res) {
    Map<String, Object> params = new HashMap<>();
    params.put("name", req.queryParams("name"));
    return new ModelAndView(params, "hello");
  }
}

