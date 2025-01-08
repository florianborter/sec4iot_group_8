package floalaalex.terminal;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Product {
    private int id;
    private String name;
    private double price;

    public Product(int id, String name, double price) {
        this.id = id;
        this.name = name;
        this.price = price;
    }

    public Product() {}

    public int getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public double getPrice() {
        return price;
    }

    // Jackson methods

    @JsonProperty("name") // Correspond au champ "name" dans le JSON
    public void setName(String name) {
        this.name = name;
    }

    @JsonProperty("price") // Correspond au champ "price" dans le JSON
    public void setPrice(double price) {
        this.price = price;
    }

    @JsonProperty("id") // Correspond au champ "id" dans le JSON
    public void setID(int id) {
        this.id = id;
    }

    @Override
    public String toString() {
        return "Product{" +
                "name='" + name + '\'' +
                ", price=" + price +
                ", id=" + id +
                '}';
    }
}
