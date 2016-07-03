package org.tplmap.webframeworks;
import spark.Request;
import spark.Response;
import spark.Route;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import java.io.StringReader;
import java.io.IOException;
import java.io.StringWriter;
import java.util.HashMap;
 
import static spark.Spark.*;
 
public class SparkApplication {

public static void main(String[] args) {
  port(15001);
  get("/freemarker", SparkApplication::freemarker);

}

public static Object freemarker(Request request, Response response) {
  
  // Get inj parameter, exit if none
  String templateStr = request.queryParams("inj");
  if(templateStr == null) {
    return "";
  }
  
  // Generate template from "inj" 
  Template tpl;
  try{
    tpl = new Template("name", new StringReader(templateStr),  new Configuration());
  }catch(IOException e){
    e.printStackTrace();
    return "";
  }
  
  // Write processed template to out
  HashMap data = new HashMap();
  StringWriter out = new StringWriter();
  try{
    tpl.process(data, out);
  }catch(TemplateException | IOException e){
    e.printStackTrace();
    return "";
  }
  
  // Return out string
  return out.toString();
}
}