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
import org.apache.velocity.VelocityContext ; 
import org.apache.velocity.app.VelocityEngine ; 
import org.apache.velocity.exception.MethodInvocationException ; 
import org.apache.velocity.exception.ParseErrorException ; 
import org.apache.velocity.exception.ResourceNotFoundException ; 
import org.apache.velocity.runtime.RuntimeConstants ; 
import org.apache.velocity.runtime.log.LogChute ; 
import org.apache.velocity.runtime.log.NullLogChute ; 

import static spark.Spark.*;
 
public class SparkApplication {

public static void main(String[] args) {
  port(15001);
  get("/freemarker", SparkApplication::freemarker);
  get("/velocity", SparkApplication::velocity);
}

public static Object velocity(Request request, Response response) {
  
  // Get inj parameter, exit if none
  String templateStr = request.queryParams("inj");
  if(templateStr == null) {
    return "";
  }
  
  LogChute velocityLogChute = new NullLogChute() ; 
  VelocityEngine velocity;
  StringWriter w;
  try{
    velocity = new VelocityEngine() ;
    // Turn off logging - catch exceptions and log ourselves
    velocity.setProperty(RuntimeConstants.RUNTIME_LOG_LOGSYSTEM, velocityLogChute) ;
    velocity.setProperty(RuntimeConstants.INPUT_ENCODING, "UTF-8") ;
    velocity.init() ;
    
    
    VelocityContext context = new VelocityContext();
    String s = templateStr;
    w = new StringWriter();
    
    velocity.evaluate( context, w, "mystring", s );

    
  }catch(Exception e){
    e.printStackTrace();
    return "";
  }
    
  // Return out string
  return w.toString();
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