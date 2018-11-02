package infrastructure.jclouds;

import java.io.IOException;
import java.util.Set;

import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableSet;
import com.google.inject.Module;
import org.apache.geode.perftest.infrastructure.InfraManager;
import org.apache.geode.perftest.infrastructure.Infrastructure;
import org.jclouds.ContextBuilder;
import org.jclouds.compute.ComputeService;
import org.jclouds.compute.ComputeServiceContext;
import org.jclouds.compute.RunNodesException;
import org.jclouds.compute.domain.ExecResponse;
import org.jclouds.compute.domain.NodeMetadata;
import org.jclouds.compute.domain.Template;
import org.jclouds.domain.Credentials;
import org.jclouds.sshj.config.SshjSshClientModule;

public class JCloudsInfraManager implements InfraManager {


  private final String cloud;
  private final String image;
  private final Supplier<Credentials> credentials;

//  public JCloudsInfraManager() {
//    cloud = "google-compute-engine";
//    image = "yardstick-tester";
//  }


  public JCloudsInfraManager(String cloud, String image, Supplier<Credentials> credentials) {
    this.cloud = cloud;
    this.image = image;
    this.credentials = credentials;
  }

  @Override
  public Infrastructure create(int numNodes) throws RunNodesException, IOException {
    ComputeServiceContext context = ContextBuilder.newBuilder(cloud)
        .modules(ImmutableSet.<Module> of(new SshjSshClientModule() ))
        .credentialsSupplier(credentials)
        .buildView(ComputeServiceContext.class);

    ComputeService client = context.getComputeService();

    Template
        template =
        client.templateBuilder()
            .imageNameMatches("yardstick-tester.*")
            .locationId("us-central1-c")
            .minCores(8)
            .build();

    Set<? extends NodeMetadata>
        nodes =
        client.createNodesInGroup("group", 1, template);


    return new TestInfraStructure(client, nodes);
  }

  private static class TestInfraStructure implements Infrastructure {
    private final Set<? extends NodeMetadata> nodes;
    private final ComputeService client;

    public TestInfraStructure(ComputeService client,
        Set<? extends NodeMetadata> nodes) {
      this.client = client;
      this.nodes = nodes;
    }

    @Override
    public Set<Node> getNodes() {
//      return this.nodes;
      return null;
    }

    @Override
    public void onNode(Node node, String[] shellCommand) throws IOException {

    }

    public String onNode(NodeMetadata node, String script) {

      ExecResponse
          result =
          client.runScriptOnNode(node.getId(), script);

      if(result.getExitStatus() != 0) {
        throw new RuntimeException("Script execution failed. " + result.getError() + " " + result.getOutput());
      }

      return result.getOutput();

    }

    @Override
    public void delete() {
      nodes.forEach(node -> client.destroyNode(node.getId()));
    }
  }
}
